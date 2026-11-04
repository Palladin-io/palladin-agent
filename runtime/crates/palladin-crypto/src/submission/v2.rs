//! Additive payload v2 inside the unchanged authenticated v1 transport.
use super::*;

const SCHEMA: &str = "palladin.agent-submission-payload.v2";

/// Values are memory-only. For TOTP, value contains a JSON object; other kinds use raw text.
pub struct SubmissionCustomFieldV2 {
    pub id: String,
    /// Omit on an update to retain the existing label. Required when creating a field.
    pub label: Option<String>,
    pub field_type: String,
    pub value: SecretString,
}

impl Drop for SubmissionCustomFieldV2 {
    fn drop(&mut self) {
        if let Some(label) = self.label.as_mut() {
            label.zeroize();
        }
    }
}

/// A sparse patch: absent fields must remain unchanged at approval.
pub struct SubmissionContentV2 {
    pub entry_type: SubmissionEntryType,
    pub username: Option<SecretString>,
    pub password: Option<SecretString>,
    pub value: Option<SecretString>,
    pub url: Option<SecretString>,
    pub notes: Option<SecretString>,
    pub custom_fields: Vec<SubmissionCustomFieldV2>,
}

impl std::fmt::Debug for SubmissionContentV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SubmissionContentV2([REDACTED])")
    }
}
impl std::fmt::Debug for SubmissionCustomFieldV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SubmissionCustomFieldV2([REDACTED])")
    }
}

pub struct OpenedSubmissionV2 {
    pub identity: SubmissionIdentity,
    pub label: Option<String>,
    pub description: Option<String>,
    pub content: SubmissionContentV2,
}

fn string(value: &Value, limit: usize) -> Result<&str, SubmissionError> {
    if value.as_str() == Some("") {
        return Ok("");
    }
    payload_string(value, limit)
}

fn validate_totp(value: &Value) -> Result<(), SubmissionError> {
    let object = value.as_object().ok_or(SubmissionError::InvalidField)?;
    check_fields(
        object,
        &["secret", "algorithm", "digits", "period"],
        &["issuer", "account"],
    )?;
    let secret = payload_string(&object["secret"], 1024)?;
    if !secret
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        || !matches!(
            object["algorithm"].as_str(),
            Some("SHA1" | "SHA256" | "SHA512")
        )
        || !matches!(object["digits"].as_u64(), Some(6 | 8))
        || !object["period"]
            .as_u64()
            .is_some_and(|period| (15..=120).contains(&period))
    {
        return Err(SubmissionError::InvalidField);
    }
    for key in ["issuer", "account"] {
        if let Some(value) = object.get(key)
            && !value.is_null()
        {
            string(value, 1024)?;
        }
    }
    Ok(())
}

fn validate(payload: &Value, identity: &SubmissionIdentity) -> Result<(), SubmissionError> {
    let object = payload.as_object().ok_or(SubmissionError::InvalidField)?;
    check_fields(
        object,
        &["schema", "identity", "content"],
        &["label", "description"],
    )?;
    if object["schema"].as_str() != Some(SCHEMA) {
        return Err(SubmissionError::InvalidField);
    }
    if canonical_json(&object["identity"])? != identity.canonical()? {
        return Err(SubmissionError::IdentityMismatch);
    }
    if let Some(label) = object.get("label") {
        payload_string(label, LABEL_MAX_BYTES)?;
    } else if identity.kind() == SubmissionKind::New {
        return Err(SubmissionError::MissingField);
    }
    if let Some(description) = object.get("description") {
        string(description, NOTES_MAX_BYTES)?;
    }
    let content = object["content"]
        .as_object()
        .ok_or(SubmissionError::InvalidField)?;
    let fields: &[&str] = match identity.entry_type {
        SubmissionEntryType::Credential => {
            &["username", "password", "url", "notes", "customFields"]
        }
        SubmissionEntryType::Key => &["value", "url", "notes", "customFields"],
    };
    check_fields(content, &[], fields)?;
    if identity.kind() == SubmissionKind::New {
        let required: &[&str] = match identity.entry_type {
            SubmissionEntryType::Credential => &["username", "password"],
            SubmissionEntryType::Key => &["value"],
        };
        for key in required {
            payload_string(
                content.get(*key).ok_or(SubmissionError::MissingField)?,
                content_limit(key),
            )?;
        }
    }
    for (key, value) in content {
        if key != "customFields" {
            string(value, content_limit(key))?;
        }
    }
    if identity.entry_type == SubmissionEntryType::Credential
        && let Some(url) = content.get("url")
        && !is_https_url(url.as_str().ok_or(SubmissionError::InvalidField)?)
    {
        return Err(SubmissionError::InvalidField);
    }
    let mut custom_count = 0;
    if let Some(custom) = content.get("customFields") {
        let custom = custom.as_array().ok_or(SubmissionError::InvalidField)?;
        if custom.len() > 64 {
            return Err(SubmissionError::FieldTooLarge);
        }
        let mut ids = std::collections::HashSet::new();
        for field in custom {
            let field = field.as_object().ok_or(SubmissionError::InvalidField)?;
            check_fields(field, &["id", "type", "value"], &["label"])?;
            let id = text(field, "id")?;
            let suffix = id
                .strip_prefix("custom:")
                .ok_or(SubmissionError::InvalidField)?;
            let parsed = Uuid::parse_str(suffix).map_err(|_| SubmissionError::InvalidField)?;
            if parsed.to_string() != suffix
                || !(1..=8).contains(&parsed.get_version_num())
                || parsed.get_variant() != uuid::Variant::RFC4122
                || !ids.insert(id)
            {
                return Err(SubmissionError::InvalidField);
            }
            if let Some(label) = field.get("label") {
                payload_string(label, 128)?;
            } else if identity.kind() == SubmissionKind::New {
                return Err(SubmissionError::MissingField);
            }
            match text(field, "type")? {
                "text" | "multiline" | "concealed" => {
                    string(&field["value"], KEY_VALUE_MAX_BYTES)?;
                }
                "totp" => validate_totp(&field["value"])?,
                _ => return Err(SubmissionError::InvalidField),
            }
            custom_count += 1;
        }
    }
    if identity.kind() == SubmissionKind::Update
        && !object.contains_key("label")
        && !object.contains_key("description")
        && !content.keys().any(|key| key != "customFields")
        && custom_count == 0
    {
        return Err(SubmissionError::MissingField);
    }
    Ok(())
}

impl SubmissionContentV2 {
    fn to_value(&self) -> Result<Value, SubmissionError> {
        let mut content = Map::new();
        for (key, value) in [
            ("username", &self.username),
            ("password", &self.password),
            ("value", &self.value),
            ("url", &self.url),
            ("notes", &self.notes),
        ] {
            if let Some(value) = value {
                content.insert(key.into(), json!(value.expose_secret()));
            }
        }
        let mut fields = Vec::new();
        for field in &self.custom_fields {
            let value = if field.field_type == "totp" {
                match serde_json::from_str(field.value.expose_secret()) {
                    Ok(value) => value,
                    Err(_) => {
                        let mut value = Value::Object(content);
                        zeroize_json(&mut value);
                        let mut value = Value::Array(fields);
                        zeroize_json(&mut value);
                        return Err(SubmissionError::InvalidInput);
                    }
                }
            } else {
                json!(field.value.expose_secret())
            };
            let mut custom = json!({"id":field.id,"type":field.field_type,"value":value});
            if let Some(label) = &field.label {
                custom["label"] = json!(label);
            }
            fields.push(custom);
        }
        if !fields.is_empty() {
            content.insert("customFields".into(), Value::Array(fields));
        }
        Ok(Value::Object(content))
    }
}

/// Produces the same transport type as v1; only the encrypted payload schema is v2.
pub fn build_agent_submission_v2(
    context: &SubmissionBuildContext<'_>,
    label: Option<&str>,
    description: Option<&str>,
    content: &SubmissionContentV2,
) -> Result<AgentEntrySubmission, SubmissionError> {
    if context.identity.entry_type != content.entry_type {
        return Err(SubmissionError::InvalidInput);
    }
    if context.identity.organization_id != context.approver.organization_id {
        return Err(SubmissionError::ContextMismatch);
    }
    let mut payload = json!({"schema":SCHEMA,"identity":context.identity.to_value(),"content":content.to_value()?});
    if let Some(label) = label {
        payload["label"] = json!(label);
    }
    if let Some(description) = description {
        payload["description"] = json!(description);
    }
    let valid = validate(&payload, &context.identity);
    let plaintext = canonical_json(&payload).map(Zeroizing::new);
    zeroize_json(&mut payload);
    valid.map_err(|_| SubmissionError::InvalidInput)?;
    let plaintext = plaintext?;
    if plaintext.len() > PAYLOAD_PLAINTEXT_MAX_BYTES {
        return Err(SubmissionError::InvalidInput);
    }
    let mut dek = Zeroizing::new([0_u8; 32]);
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(dek.as_mut()).map_err(|_| SubmissionError::RandomGenerationFailed)?;
    getrandom::fill(&mut nonce).map_err(|_| SubmissionError::RandomGenerationFailed)?;
    let dek = SecretBox::new(Box::new(*dek));
    let encoded_payload = encrypt_payload(&context.identity, &dek, &nonce, plaintext.as_slice())?;
    seal_revision(
        context.identity.clone(),
        encoded_payload,
        &dek,
        1,
        context.agent_access_epoch,
        context.agent_key_version,
        context.agent_encryption_public_key,
        context.agent_signing,
        context.approver,
    )
}

pub fn open_agent_submission_v2(
    submission: &AgentEntrySubmission,
    authority: &SubmissionAuthority<'_>,
) -> Result<OpenedSubmissionV2, SubmissionError> {
    let mut payload = decrypt_submission_payload(submission, authority)?;
    let result = (|| {
        validate(&payload, &submission.identity)?;
        let content = &payload["content"];
        let optional = |key: &str| {
            content
                .get(key)
                .and_then(Value::as_str)
                .map(|value| SecretString::from(value.to_owned()))
        };
        let mut custom_fields = Vec::new();
        if let Some(fields) = content.get("customFields").and_then(Value::as_array) {
            for field in fields {
                let value = if field["type"] == "totp" {
                    serde_json::to_string(&field["value"])
                        .map_err(|_| SubmissionError::InvalidField)?
                } else {
                    field["value"]
                        .as_str()
                        .ok_or(SubmissionError::InvalidField)?
                        .to_owned()
                };
                custom_fields.push(SubmissionCustomFieldV2 {
                    id: field["id"]
                        .as_str()
                        .ok_or(SubmissionError::InvalidField)?
                        .to_owned(),
                    label: field
                        .get("label")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    field_type: field["type"]
                        .as_str()
                        .ok_or(SubmissionError::InvalidField)?
                        .to_owned(),
                    value: SecretString::from(value),
                });
            }
        }
        Ok(OpenedSubmissionV2 {
            identity: submission.identity.clone(),
            label: payload
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_owned),
            description: payload
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned),
            content: SubmissionContentV2 {
                entry_type: submission.identity.entry_type,
                username: optional("username"),
                password: optional("password"),
                value: optional("value"),
                url: optional("url"),
                notes: optional("notes"),
                custom_fields,
            },
        })
    })();
    zeroize_json(&mut payload);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SubmissionIdentity {
        SubmissionIdentity {
            organization_id: Uuid::from_u128(1),
            submission_id: Uuid::from_u128(2),
            agent_id: Uuid::from_u128(3),
            entry_type: SubmissionEntryType::Credential,
            target: SubmissionTarget::Update {
                vault_id: Uuid::from_u128(4),
                entry_id: Uuid::from_u128(5),
                expected_entry_revision: 1,
            },
        }
    }

    #[test]
    fn sparse_v2_updates_do_not_require_password() {
        let identity = identity();
        for content in [json!({"username":"alice"}), json!({})] {
            let payload = json!({"schema":"palladin.agent-submission-payload.v2", "identity":identity.to_value(), "description":"New description", "content":content});
            assert!(validate(&payload, &identity).is_ok());
            assert!(
                parse_payload(&payload, &identity).is_err(),
                "v1 must remain closed"
            );
        }
    }

    #[test]
    fn v2_rejects_noop_and_wrong_type_fields() {
        let identity = identity();
        for content in [
            json!({}),
            json!({"value":"wrong type"}),
            json!({"password":42}),
        ] {
            let payload = json!({"schema":"palladin.agent-submission-payload.v2", "identity":identity.to_value(), "content":content});
            assert!(validate(&payload, &identity).is_err());
        }
    }

    #[test]
    fn custom_fields_are_typed_unique_bounded_and_closed() {
        let identity = identity();
        let field = json!({"id":"custom:11112222-4333-8444-9555-666677778888","type":"totp","value":{"secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}});
        let payload = |fields: Value| json!({"schema":"palladin.agent-submission-payload.v2","identity":identity.to_value(),"content":{"customFields":fields}});
        assert!(validate(&payload(json!([field.clone()])), &identity).is_ok());
        assert!(validate(&payload(json!([field.clone(), field.clone()])), &identity).is_err());
        for bad in [
            json!({"type":"unknown"}),
            json!({"value":"raw seed"}),
            json!({"extra":"value"}),
            json!({"id":"custom:00000000-0000-0000-0000-000000000000"}),
        ] {
            let mut changed = field.clone();
            for (key, value) in bad.as_object().unwrap() {
                changed[key] = value.clone();
            }
            assert!(validate(&payload(json!([changed])), &identity).is_err());
        }
        let mut changed = field;
        changed["value"]["digits"] = json!(7);
        assert!(validate(&payload(json!([changed])), &identity).is_err());
    }

    #[test]
    fn new_v2_credentials_require_username_and_password() {
        let mut identity = identity();
        identity.target = SubmissionTarget::New {
            suggested_vault_id: None,
        };
        for content in [json!({"username":"alice"}), json!({"password":"synthetic"})] {
            let payload = json!({"schema":"palladin.agent-submission-payload.v2", "identity":identity.to_value(), "label":"Example", "content":content});
            assert!(validate(&payload, &identity).is_err());
        }
        let payload = json!({"schema":"palladin.agent-submission-payload.v2", "identity":identity.to_value(), "label":"Example", "content":{"username":"alice","password":"synthetic"}});
        assert!(validate(&payload, &identity).is_ok());
    }
}
