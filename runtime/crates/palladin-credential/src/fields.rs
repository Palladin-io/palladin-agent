use palladin_core::terminal::shorten_identifier;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::secret::{CustomField, CustomFieldType, ParsedSecret, parse_totp_value};
use crate::totp::{TotpCode, generate_totp, generate_totp_at};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct FieldSelector {
    pub field: Option<String>,
    pub field_id: Option<String>,
}

impl std::fmt::Debug for FieldSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FieldSelector([REDACTED])")
    }
}

pub enum ResolvedField {
    Value {
        label: String,
        field_type: ResolvedFieldType,
        value: SecretString,
    },
    Totp {
        label: String,
        code: SecretString,
        expires_in: u64,
    },
}

impl std::fmt::Debug for ResolvedField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value { field_type, .. } => formatter
                .debug_struct("ResolvedField::Value")
                .field("label", &"[REDACTED]")
                .field("field_type", field_type)
                .field("value", &"[REDACTED]")
                .finish(),
            Self::Totp { expires_in, .. } => formatter
                .debug_struct("ResolvedField::Totp")
                .field("label", &"[REDACTED]")
                .field("code", &"[REDACTED]")
                .field("expires_in", expires_in)
                .finish(),
        }
    }
}

impl ResolvedField {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &str {
        match self {
            Self::Value { value, .. } => value.expose_secret(),
            Self::Totp { code, .. } => code.expose_secret(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedFieldType {
    WellKnown,
    Text,
    Concealed,
    Multiline,
}

pub fn resolve_field(
    secret: &ParsedSecret,
    selector: &FieldSelector,
) -> Result<ResolvedField, FieldSelectionError> {
    resolve_field_with_totp(secret, selector, |field| {
        let params = parse_totp_value(field).ok_or(FieldSelectionError::InvalidTotpDescriptor)?;
        generate_totp(&params).map_err(|_| FieldSelectionError::InvalidTotpDescriptor)
    })
}

pub fn resolve_field_at(
    secret: &ParsedSecret,
    selector: &FieldSelector,
    unix_seconds: u64,
) -> Result<ResolvedField, FieldSelectionError> {
    resolve_field_with_totp(secret, selector, |field| {
        let params = parse_totp_value(field).ok_or(FieldSelectionError::InvalidTotpDescriptor)?;
        generate_totp_at(&params, unix_seconds)
            .map_err(|_| FieldSelectionError::InvalidTotpDescriptor)
    })
}

fn resolve_field_with_totp(
    secret: &ParsedSecret,
    selector: &FieldSelector,
    totp: impl FnOnce(&str) -> Result<TotpCode, FieldSelectionError>,
) -> Result<ResolvedField, FieldSelectionError> {
    let selected = if let Some(id) = selector.field_id.as_deref() {
        Selected::Custom(resolve_by_id(secret, id.trim())?)
    } else if let Some(label) = selector.field.as_deref() {
        resolve_by_label(secret, label.trim())?
    } else {
        return Err(FieldSelectionError::MissingSelector);
    };
    match selected {
        Selected::WellKnown(label, value) => Ok(ResolvedField::Value {
            label,
            field_type: ResolvedFieldType::WellKnown,
            value,
        }),
        Selected::Custom(field) if field.field_type == CustomFieldType::Totp => {
            let code = totp(field.value.expose_secret())?;
            Ok(ResolvedField::Totp {
                label: field.label.clone(),
                code: code.code,
                expires_in: code.expires_in,
            })
        }
        Selected::Custom(field) => Ok(ResolvedField::Value {
            label: field.label.clone(),
            field_type: match field.field_type {
                CustomFieldType::Text => ResolvedFieldType::Text,
                CustomFieldType::Concealed => ResolvedFieldType::Concealed,
                CustomFieldType::Multiline => ResolvedFieldType::Multiline,
                CustomFieldType::Totp => unreachable!("TOTP handled above"),
            },
            value: field.value.clone(),
        }),
        Selected::LegacyTotp(value) => {
            let code = totp(value.expose_secret())?;
            Ok(ResolvedField::Totp {
                label: "totp".to_owned(),
                code: code.code,
                expires_in: code.expires_in,
            })
        }
    }
}

enum Selected<'a> {
    WellKnown(String, SecretString),
    Custom(&'a CustomField),
    LegacyTotp(&'a SecretString),
}

fn resolve_by_id<'a>(
    secret: &'a ParsedSecret,
    id: &str,
) -> Result<&'a CustomField, FieldSelectionError> {
    let matches = secret
        .custom_fields
        .iter()
        .filter(|field| field.id == id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(FieldSelectionError::UnknownFieldId(shorten_identifier(id))),
        [field] => Ok(field),
        _ => Err(FieldSelectionError::DuplicateFieldId(shorten_identifier(
            id,
        ))),
    }
}

fn resolve_by_label<'a>(
    secret: &'a ParsedSecret,
    label: &str,
) -> Result<Selected<'a>, FieldSelectionError> {
    let matches = secret
        .custom_fields
        .iter()
        .filter(|field| labels_equal(&field.label, label))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [field] => return Ok(Selected::Custom(field)),
        [_, _, ..] => {
            return Err(FieldSelectionError::DuplicateLabel {
                label: label.to_owned(),
                ids: matches
                    .iter()
                    .map(|field| shorten_identifier(&field.id))
                    .collect(),
            });
        }
        [] => {}
    }

    let lower = Zeroizing::new(label.to_lowercase());
    if lower.as_str() == "totp"
        && let Some(value) = &secret.legacy_totp
    {
        return Ok(Selected::LegacyTotp(value));
    }
    let value = match lower.as_str() {
        "username" => secret.username.clone(),
        "password" | "value" => Some(secret.password.clone()),
        "url" => secret.url.clone(),
        "notes" => secret.notes.clone(),
        _ => return Err(FieldSelectionError::UnknownField(label.to_owned())),
    }
    .filter(|value| !value.expose_secret().is_empty())
    .ok_or_else(|| FieldSelectionError::FieldAbsent(label.to_owned()))?;
    Ok(Selected::WellKnown(lower.to_string(), value))
}

fn labels_equal(left: &str, right: &str) -> bool {
    let left = Zeroizing::new(left.to_lowercase());
    let right = Zeroizing::new(right.to_lowercase());
    *left == *right
}

pub fn redact_totp_secrets(
    plaintext: &[u8],
    unix_seconds: u64,
) -> Result<SecretString, FieldRedactionError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| FieldRedactionError::InvalidUtf8)?;
    let mut value = match serde_json::from_str::<Value>(text) {
        Ok(value) => SensitiveJson(value),
        Err(_) => return Ok(text.to_owned().into()),
    };
    let Some(object) = value.0.as_object_mut() else {
        return Ok(text.to_owned().into());
    };
    let mut redacted = false;
    if let Some(legacy) = object.get("totp") {
        let descriptor = Zeroizing::new(match legacy {
            Value::String(value) => value.clone(),
            value => serde_json::to_string(value).unwrap_or_default(),
        });
        object.insert(
            "totp".to_owned(),
            totp_replacement(&descriptor, unix_seconds),
        );
        redacted = true;
    }
    if let Some(fields) = object.get_mut("fields").and_then(Value::as_array_mut) {
        for field in fields {
            let Some(object) = field.as_object_mut() else {
                continue;
            };
            if object.get("type").and_then(Value::as_str) != Some("totp") {
                continue;
            }
            redacted = true;
            let descriptor = Zeroizing::new(match object.get("value") {
                Some(Value::String(value)) => value.clone(),
                Some(value @ Value::Object(_)) => serde_json::to_string(value).unwrap_or_default(),
                _ => String::new(),
            });
            object.insert(
                "value".to_owned(),
                totp_replacement(&descriptor, unix_seconds),
            );
        }
    }
    if !redacted {
        return Ok(text.to_owned().into());
    }
    serde_json::to_string(&value.0)
        .map(Into::into)
        .map_err(|_| FieldRedactionError::Serialization)
}

fn totp_replacement(descriptor: &str, unix_seconds: u64) -> Value {
    parse_totp_value(descriptor)
        .and_then(|params| generate_totp_at(&params, unix_seconds).ok())
        .map_or_else(
            || json!({"error":"TOTP descriptor is invalid and was withheld"}),
            |code| {
                json!({
                    "code": code.code.expose_secret(),
                    "expiresIn": code.expires_in,
                    "note": "TOTP secret withheld - use --field to get a fresh code"
                })
            },
        )
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FieldSelectionError {
    #[error("no field selector was provided")]
    MissingSelector,
    #[error("no custom field has id {0}")]
    UnknownFieldId(String),
    #[error("custom field id {0} is duplicated; the credential is ambiguous")]
    DuplicateFieldId(String),
    #[error("multiple fields are labelled {label}; use fieldId: {ids:?}")]
    DuplicateLabel { label: String, ids: Vec<String> },
    #[error("no field is named {0}")]
    UnknownField(String),
    #[error("this entry has no value for field {0}")]
    FieldAbsent(String),
    #[error("the selected TOTP descriptor is invalid")]
    InvalidTotpDescriptor,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FieldRedactionError {
    #[error("decrypted credential is not valid UTF-8")]
    InvalidUtf8,
    #[error("could not serialize the TOTP-redacted credential")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        FieldSelectionError, FieldSelector, ResolvedField, redact_totp_secrets, resolve_field_at,
    };
    use crate::secret::parse_secret;

    const TOTP: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn custom_fields_shadow_well_known_and_duplicate_labels_require_field_id() {
        let parsed = parse_secret(
            br#"{"password":"primary","fields":[{"id":"a","label":"password","type":"text","value":"custom"},{"id":"b","label":"Token","type":"text","value":"one"},{"id":"c","label":"Token","type":"text","value":"two"}]}"#,
        )
        .expect("parse");
        assert_eq!(
            resolve_field_at(
                &parsed,
                &FieldSelector {
                    field: Some("password".to_owned()),
                    field_id: None,
                },
                59,
            )
            .expect("custom shadow")
            .expose_for_authorized_operation(),
            "custom"
        );
        assert!(matches!(
            resolve_field_at(
                &parsed,
                &FieldSelector {
                    field: Some("token".to_owned()),
                    field_id: None,
                },
                59,
            ),
            Err(FieldSelectionError::DuplicateLabel { .. })
        ));
    }

    #[test]
    fn duplicate_field_ids_fail_closed() {
        let parsed = parse_secret(
            br#"{"value":"x","fields":[{"id":"same","label":"one","type":"text","value":"1"},{"id":"same","label":"two","type":"text","value":"2"}]}"#,
        )
        .expect("parse");
        assert!(matches!(
            resolve_field_at(
                &parsed,
                &FieldSelector {
                    field: None,
                    field_id: Some("same".to_owned()),
                },
                59,
            ),
            Err(FieldSelectionError::DuplicateFieldId(_))
        ));
    }

    #[test]
    fn totp_selection_returns_only_the_current_code() {
        let payload = format!(
            r#"{{"value":"x","fields":[{{"id":"otp","label":"Authenticator","type":"totp","value":{{"secret":"{TOTP}"}}}}]}}"#
        );
        let parsed = parse_secret(payload.as_bytes()).expect("parse");
        let resolved = resolve_field_at(
            &parsed,
            &FieldSelector {
                field: Some("authenticator".to_owned()),
                field_id: None,
            },
            59,
        )
        .expect("TOTP");
        assert!(matches!(resolved, ResolvedField::Totp { .. }));
        assert_eq!(resolved.expose_for_authorized_operation(), "287082");
        assert!(!format!("{resolved:?}").contains("287082"));
    }

    #[test]
    fn full_get_redacts_valid_and_malformed_totp_values() {
        let payload = format!(
            r#"{{"v":2,"fields":[{{"id":"a","type":"totp","value":{{"secret":"{TOTP}"}}}},{{"id":"b","type":"totp","value":{{"secret":"must-not-leak","period":0}}}}]}}"#
        );
        let redacted = redact_totp_secrets(payload.as_bytes(), 59).expect("redact");
        assert!(!redacted.expose_secret().contains(TOTP));
        assert!(!redacted.expose_secret().contains("must-not-leak"));
        assert!(redacted.expose_secret().contains("287082"));
        assert!(redacted.expose_secret().contains("withheld"));
    }

    #[test]
    fn legacy_top_level_totp_is_resolved_and_redacted() {
        let payload = format!(
            r#"{{"username":"alice","password":"pw","totp":"otpauth://totp/GitHub?secret={TOTP}"}}"#
        );
        let parsed = parse_secret(payload.as_bytes()).expect("parse");
        let resolved = resolve_field_at(
            &parsed,
            &FieldSelector {
                field: Some("totp".to_owned()),
                field_id: None,
            },
            59,
        )
        .expect("legacy TOTP");
        assert_eq!(resolved.expose_for_authorized_operation(), "287082");
        let redacted = redact_totp_secrets(payload.as_bytes(), 59).expect("redact");
        assert!(!redacted.expose_secret().contains(TOTP));
        assert!(redacted.expose_secret().contains("287082"));
    }
}
