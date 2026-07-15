use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::totp::{TotpAlgorithm, TotpParams};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomFieldType {
    Text,
    Concealed,
    Multiline,
    Totp,
}

pub struct CustomField {
    pub id: String,
    pub label: String,
    pub field_type: CustomFieldType,
    pub value: SecretString,
    pub agent_visible: bool,
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustomField")
            .field("id", &"[REDACTED]")
            .field("label", &"[REDACTED]")
            .field("field_type", &self.field_type)
            .field("value", &"[REDACTED]")
            .field("agent_visible", &self.agent_visible)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ScriptRef {
    pub env: String,
    pub vault_id: Option<String>,
    pub entry_id: String,
    pub field: Option<String>,
}

impl std::fmt::Debug for ScriptRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScriptRef([REDACTED])")
    }
}

pub struct ScriptPayload {
    pub script: SecretString,
    pub interpreter: String,
    pub refs: Vec<ScriptRef>,
}

impl std::fmt::Debug for ScriptPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptPayload")
            .field("script", &"[REDACTED]")
            .field("interpreter", &self.interpreter)
            .field("refs_count", &self.refs.len())
            .finish()
    }
}

pub struct ParsedSecret {
    pub username: Option<SecretString>,
    pub password: SecretString,
    pub url: Option<SecretString>,
    pub notes: Option<SecretString>,
    pub legacy_totp: Option<SecretString>,
    pub fields: BTreeMap<String, SecretString>,
    pub custom_fields: Vec<CustomField>,
    pub script: Option<ScriptPayload>,
}

impl std::fmt::Debug for ParsedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedSecret")
            .field("username", &self.username.as_ref().map(|_| "[REDACTED]"))
            .field("password", &"[REDACTED]")
            .field("url", &self.url.as_ref().map(|_| "[REDACTED]"))
            .field("notes", &self.notes.as_ref().map(|_| "[REDACTED]"))
            .field(
                "legacy_totp",
                &self.legacy_totp.as_ref().map(|_| "[REDACTED]"),
            )
            .field("field_count", &self.fields.len())
            .field("custom_field_count", &self.custom_fields.len())
            .field("script", &self.script)
            .finish()
    }
}

const STRUCTURAL_KEYS: &[&str] = &["v", "fields", "script", "interpreter", "refs", "totp"];

pub fn parse_secret(plaintext: &[u8]) -> Result<ParsedSecret, SecretParseError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| SecretParseError::InvalidUtf8)?;
    let value = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => SensitiveJson(Value::Object(object)),
        Ok(mut other) => {
            zeroize_json(&mut other);
            return Ok(raw_secret(text));
        }
        Err(_) => return Ok(raw_secret(text)),
    };
    let object = value.0.as_object().ok_or(SecretParseError::InvalidJson)?;
    let custom_fields = parse_custom_fields(object.get("fields"));
    let script = parse_script(object)?;

    let username = string(object.get("username")).map(Into::into);
    let password = string(object.get("password"))
        .or_else(|| string(object.get("value")))
        .unwrap_or_default()
        .into();
    let url = string(object.get("url")).map(Into::into);
    let notes = string(object.get("notes")).map(Into::into);
    let legacy_totp = string(object.get("totp")).map(Into::into);
    let mut fields = BTreeMap::new();
    for (key, value) in object {
        if !STRUCTURAL_KEYS.contains(&key.as_str())
            && let Some(value) = value.as_str()
        {
            fields.insert(key.clone(), value.to_owned().into());
        }
    }
    for field in &custom_fields {
        if field.field_type == CustomFieldType::Totp {
            continue;
        }
        let key = env_field_key(&field.label);
        if !key.is_empty() && !fields.contains_key(&key) {
            fields.insert(key, field.value.clone());
        }
    }

    Ok(ParsedSecret {
        username,
        password,
        url,
        notes,
        legacy_totp,
        fields,
        custom_fields,
        script,
    })
}

fn raw_secret(plaintext: &str) -> ParsedSecret {
    let password: SecretString = plaintext.to_owned().into();
    let mut fields = BTreeMap::new();
    fields.insert("value".to_owned(), password.clone());
    ParsedSecret {
        username: None,
        password,
        url: None,
        notes: None,
        legacy_totp: None,
        fields,
        custom_fields: Vec::new(),
        script: None,
    }
}

fn parse_custom_fields(value: Option<&Value>) -> Vec<CustomField> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let id = object.get("id")?.as_str()?.to_owned();
            let label = object.get("label")?.as_str()?.trim().to_owned();
            let field_type = match object.get("type")?.as_str()? {
                "text" => CustomFieldType::Text,
                "concealed" => CustomFieldType::Concealed,
                "multiline" => CustomFieldType::Multiline,
                "totp" => CustomFieldType::Totp,
                _ => return None,
            };
            let value = match object.get("value")? {
                Value::String(value) => value.clone(),
                Value::Object(value) => serde_json::to_string(value).ok()?,
                _ => return None,
            };
            Some(CustomField {
                id,
                label,
                field_type,
                value: value.into(),
                agent_visible: object.get("agentVisible") == Some(&Value::Bool(true)),
            })
        })
        .collect()
}

fn parse_script(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<ScriptPayload>, SecretParseError> {
    let Some(script) = object.get("script").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(interpreter) = object.get("interpreter").and_then(Value::as_str) else {
        return Ok(None);
    };
    let refs = parse_script_refs(object.get("refs"))?;
    Ok(Some(ScriptPayload {
        script: script.to_owned().into(),
        interpreter: interpreter.trim().to_owned(),
        refs,
    }))
}

fn parse_script_refs(value: Option<&Value>) -> Result<Vec<ScriptRef>, SecretParseError> {
    let Some(entries) = value else {
        return Ok(Vec::new());
    };
    let Some(entries) = entries.as_array() else {
        return Err(SecretParseError::InvalidScriptReference);
    };
    entries
        .iter()
        .map(|entry| {
            let object = entry
                .as_object()
                .ok_or(SecretParseError::InvalidScriptReference)?;
            let env = object
                .get("env")
                .or_else(|| object.get("placeholder"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(SecretParseError::InvalidScriptReference)?;
            let entry_id = object
                .get("entryId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(SecretParseError::InvalidScriptReference)?;
            let optional = |key: &str| {
                object
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            };
            Ok(ScriptRef {
                env: env.to_owned(),
                vault_id: optional("vaultId"),
                entry_id: entry_id.to_owned(),
                field: optional("field"),
            })
        })
        .collect()
}

pub fn parse_totp_params(value: &str) -> Option<TotpParams> {
    let mut json = SensitiveJson(serde_json::from_str(value).ok()?);
    let object = json.0.as_object_mut()?;
    let secret = object.get("secret")?.as_str()?.to_owned();
    let mut params = TotpParams::new(secret);
    params.algorithm =
        object
            .get("algorithm")
            .and_then(Value::as_str)
            .map_or(TotpAlgorithm::Sha1, |algorithm| {
                if algorithm.eq_ignore_ascii_case("SHA256") {
                    TotpAlgorithm::Sha256
                } else if algorithm.eq_ignore_ascii_case("SHA512") {
                    TotpAlgorithm::Sha512
                } else {
                    TotpAlgorithm::Sha1
                }
            });
    if let Some(digits) = object
        .get("digits")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    {
        params.digits = digits;
    }
    if let Some(period) = object.get("period").and_then(Value::as_u64) {
        params.period = period;
    }
    Some(params)
}

pub fn parse_totp_value(value: &str) -> Option<TotpParams> {
    if let Some(params) = parse_totp_params(value) {
        return Some(params);
    }
    let trimmed = value.trim();
    if trimmed
        .get(.."otpauth://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
    {
        return parse_otpauth_uri(value);
    }
    Some(TotpParams::new(trimmed.to_owned()))
}

fn parse_otpauth_uri(value: &str) -> Option<TotpParams> {
    const PREFIX: &str = "otpauth://totp/";

    let trimmed = value.trim();
    let (location, query) = trimmed.split_once('?')?;
    if location.len() <= PREFIX.len()
        || !location
            .get(..PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
    {
        return None;
    }

    let mut secret = None::<Zeroizing<String>>;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6_u32;
    let mut period = 30_u64;
    for pair in query.split('&') {
        let (name, encoded) = pair.split_once('=').unwrap_or((pair, ""));
        let plus_normalized = Zeroizing::new(encoded.replace('+', "%20"));
        let decoded = Zeroizing::new(
            percent_decode_str(&plus_normalized)
                .decode_utf8()
                .ok()?
                .into_owned(),
        );
        if name.eq_ignore_ascii_case("secret") {
            secret = Some(decoded);
        } else if name.eq_ignore_ascii_case("algorithm") {
            algorithm = if decoded.eq_ignore_ascii_case("SHA256") {
                TotpAlgorithm::Sha256
            } else if decoded.eq_ignore_ascii_case("SHA512") {
                TotpAlgorithm::Sha512
            } else {
                TotpAlgorithm::Sha1
            };
        } else if name.eq_ignore_ascii_case("digits") {
            digits = decoded.parse::<u32>().ok()?;
        } else if name.eq_ignore_ascii_case("period") {
            period = decoded.parse::<u64>().ok()?;
        }
    }
    let secret = secret?;
    if secret.trim().is_empty() {
        return None;
    }

    let mut params = TotpParams::new(secret.trim().to_owned());
    params.algorithm = algorithm;
    params.digits = digits;
    params.period = period;
    Some(params)
}

#[must_use]
pub fn env_field_key(label: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in label.trim().chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('_');
            }
            output.push(character.to_ascii_uppercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    output
}

fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
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

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecretParseError {
    #[error("decrypted credential is not valid UTF-8")]
    InvalidUtf8,
    #[error("decrypted credential contains invalid JSON")]
    InvalidJson,
    #[error("Script entry contains a malformed credential reference")]
    InvalidScriptReference,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        CustomFieldType, SecretParseError, env_field_key, parse_secret, parse_totp_params,
        parse_totp_value,
    };

    #[test]
    fn parses_raw_v1_v2_and_unknown_additive_fields() {
        let raw = parse_secret(b"raw-secret-token").expect("raw");
        let raw_matches = raw.password.expose_secret() == "raw-secret-token";
        assert!(raw_matches, "raw credential diverged");
        let v1 = parse_secret(br#"{"username":"alice","password":"hunter2"}"#).expect("v1");
        let username_matches = v1.username.expect("username").expose_secret() == "alice";
        assert!(username_matches, "credential username diverged");
        let v2 = parse_secret(
            br#"{"v":2,"value":"key","future":"kept","fields":[{"id":"f1","label":"Recovery email","type":"text","value":"a@b.com"},{"id":"future","label":"Future","type":"date","value":"ignore"}]}"#,
        )
        .expect("v2");
        assert_eq!(v2.custom_fields.len(), 1);
        assert_eq!(v2.custom_fields[0].field_type, CustomFieldType::Text);
        let custom_field_matches = v2.fields["RECOVERY_EMAIL"].expose_secret() == "a@b.com";
        assert!(custom_field_matches, "custom credential field diverged");
        let future_field_matches = v2.fields["future"].expose_secret() == "kept";
        assert!(
            future_field_matches,
            "forward-compatible credential field diverged"
        );
        assert!(!format!("{v2:?}").contains("a@b.com"));
    }

    #[test]
    fn totp_objects_are_normalized_but_never_added_to_injection_fields() {
        let parsed = parse_secret(
            br#"{"value":"x","fields":[{"id":"otp","label":"Authy","type":"totp","value":{"secret":"JBSWY3DP","period":60}}]}"#,
        )
        .expect("secret");
        assert!(!parsed.fields.contains_key("AUTHY"));
        let params =
            parse_totp_params(parsed.custom_fields[0].value.expose_secret()).expect("TOTP");
        assert_eq!(params.period, 60);
    }

    #[test]
    fn malformed_script_refs_fail_closed_instead_of_running_with_missing_secrets() {
        let result = parse_secret(
            br#"{"script":"echo $TOKEN","interpreter":"sh","refs":[{"env":"TOKEN"}]}"#,
        );
        assert_eq!(
            result.expect_err("malformed ref"),
            SecretParseError::InvalidScriptReference
        );
    }

    #[test]
    fn parses_script_refs_and_legacy_placeholder() {
        let parsed = parse_secret(
            br#"{"script":"echo hi","interpreter":" sh ","refs":[{"placeholder":"TOKEN","entryId":"e1"}]}"#,
        )
        .expect("script");
        let script = parsed.script.expect("Script payload");
        assert_eq!(script.interpreter, "sh");
        assert_eq!(script.refs[0].env, "TOKEN");
        assert_eq!(script.refs[0].vault_id, None);
    }

    #[test]
    fn env_keys_match_typescript_sanitization() {
        assert_eq!(env_field_key("Recovery email"), "RECOVERY_EMAIL");
        assert_eq!(env_field_key("  API-Key!! "), "API_KEY");
    }

    #[test]
    fn legacy_top_level_otpauth_is_kept_out_of_generic_fields_and_parsed_locally() {
        let parsed = parse_secret(
            br#"{"username":"alice","password":"pw","totp":"otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30"}"#,
        )
        .expect("legacy TOTP");
        assert!(!parsed.fields.contains_key("totp"));
        let value = parsed.legacy_totp.expect("legacy value");
        let params = parse_totp_value(value.expose_secret()).expect("URI");
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 30);
    }
}
