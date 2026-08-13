use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    AadField, AadProfile, AadValue, CryptoError, EnvelopeHeader, SecretBytes, X25519Identity,
    decode_base64url, decrypt_envelope, key_fingerprint, open_sealed_box,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantEnvelopeV2 {
    pub organization_id: Uuid,
    pub vault_id: Uuid,
    pub grant_id: Uuid,
    pub agent_id: Uuid,
    pub entry_id: Uuid,
    pub approved_methods: u16,
    pub grant_envelope_revision: u64,
    pub entry_revision: u64,
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub grant_key_version: u32,
    pub member_key_generation: u32,
    pub recipient_agent_key_version: u32,
    pub field_ids: Vec<String>,
    pub ciphertext: String,
    pub nonce: String,
    pub agent_wrapped_grant_dek: String,
    pub agent_wrapper_suite: u16,
    pub agent_key_fingerprint: String,
    pub envelope_expires_at: Option<String>,
    pub envelope_remaining_uses: Option<u32>,
}

pub struct DecryptedGrantPayload(SecretBytes);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedGrantContext {
    pub organization_id: Uuid,
    pub vault_id: Uuid,
    pub entry_id: Uuid,
    pub agent_id: Uuid,
    pub requested_method: u16,
    pub now: OffsetDateTime,
}

impl DecryptedGrantPayload {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.0.expose_for_crypto_operation()
    }
}

impl std::fmt::Debug for DecryptedGrantPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecryptedGrantPayload([REDACTED])")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantPayload {
    approved_methods: u16,
    entry_revision: String,
    fields: BTreeMap<String, serde_json::Value>,
}

impl Drop for GrantPayload {
    fn drop(&mut self) {
        self.entry_revision.zeroize();
        for value in self.fields.values_mut() {
            zeroize_json(value);
        }
    }
}

pub fn decrypt_grant_payload(
    envelope: &GrantEnvelopeV2,
    identity: &X25519Identity,
    expected: ExpectedGrantContext,
) -> Result<DecryptedGrantPayload, CryptoError> {
    if envelope.organization_id != expected.organization_id
        || envelope.vault_id != expected.vault_id
        || envelope.entry_id != expected.entry_id
        || envelope.agent_id != expected.agent_id
        || !matches!(expected.requested_method, 1 | 2 | 4)
        || envelope.approved_methods & expected.requested_method != expected.requested_method
        || envelope.approved_methods == 0
        || envelope.approved_methods & !7 != 0
        || envelope.agent_wrapper_suite != 1
        || envelope.field_ids.is_empty()
        || envelope.field_ids.len() > 256
        || !strict_field_ids(&envelope.field_ids)
    {
        return Err(CryptoError::InvalidProfile);
    }
    if envelope
        .envelope_remaining_uses
        .is_some_and(|remaining| remaining == 0)
    {
        return Err(CryptoError::StaleInput);
    }
    if let Some(expires_at) = &envelope.envelope_expires_at {
        let expires_at = OffsetDateTime::parse(expires_at, &Rfc3339)
            .map_err(|_| CryptoError::InvalidEncoding)?;
        if expires_at <= expected.now {
            return Err(CryptoError::StaleInput);
        }
    }
    let fingerprint = decode_32(&envelope.agent_key_fingerprint)?;
    if fingerprint != key_fingerprint(1, identity.public_key())? {
        return Err(CryptoError::AuthenticationFailed);
    }
    let wrapped = decode_base64url(&envelope.agent_wrapped_grant_dek)?;
    let grant_dek = open_sealed_box(&wrapped, identity)?;
    let nonce = decode_base64url(&envelope.nonce)?;
    let ciphertext = decode_base64url(&envelope.ciphertext)?;
    let header = EnvelopeHeader {
        protocol_version: envelope.protocol_version,
        algorithm_suite: envelope.algorithm_suite,
        resource_kind: 4,
        projection_kind: 6,
        resource_revision: envelope.grant_envelope_revision,
        key_version: envelope.grant_key_version,
        member_key_generation: envelope.member_key_generation,
    };
    let mut aad = vec![
        AadField {
            tag: 1,
            value: AadValue::U16(envelope.protocol_version),
        },
        AadField {
            tag: 2,
            value: AadValue::U16(envelope.algorithm_suite),
        },
        AadField {
            tag: 3,
            value: AadValue::U16(4),
        },
        AadField {
            tag: 4,
            value: AadValue::Uuid(envelope.organization_id),
        },
        AadField {
            tag: 5,
            value: AadValue::Uuid(envelope.vault_id),
        },
        AadField {
            tag: 6,
            value: AadValue::Uuid(envelope.entry_id),
        },
        AadField {
            tag: 7,
            value: AadValue::U16(6),
        },
        AadField {
            tag: 8,
            value: AadValue::U64(envelope.grant_envelope_revision),
        },
        AadField {
            tag: 9,
            value: AadValue::U32(envelope.grant_key_version),
        },
        AadField {
            tag: 10,
            value: AadValue::U32(envelope.member_key_generation),
        },
        AadField {
            tag: 11,
            value: AadValue::Uuid(envelope.grant_id),
        },
        AadField {
            tag: 13,
            value: AadValue::Uuid(envelope.agent_id),
        },
        AadField {
            tag: 14,
            value: AadValue::U16(envelope.approved_methods),
        },
    ];
    if let Some(expires_at) = &envelope.envelope_expires_at {
        aad.push(AadField {
            tag: 15,
            value: AadValue::Instant(expires_at.clone()),
        });
    }
    if let Some(remaining) = envelope.envelope_remaining_uses {
        aad.push(AadField {
            tag: 16,
            value: AadValue::U32(remaining),
        });
    }
    aad.extend([
        AadField {
            tag: 17,
            value: AadValue::U32(envelope.recipient_agent_key_version),
        },
        AadField {
            tag: 18,
            value: AadValue::Bytes(fingerprint.to_vec()),
        },
        AadField {
            tag: 19,
            value: AadValue::U64(envelope.entry_revision),
        },
    ]);
    let plaintext = decrypt_envelope(
        AadProfile::GrantPayload,
        header,
        grant_dek.expose_for_crypto_operation(),
        &nonce,
        &aad,
        &ciphertext,
    )?;
    let payload: GrantPayload = serde_json::from_slice(plaintext.expose_for_crypto_operation())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if payload.approved_methods != envelope.approved_methods
        || payload.entry_revision != envelope.entry_revision.to_string()
        || payload.fields.keys().cloned().collect::<BTreeSet<_>>()
            != envelope.field_ids.iter().cloned().collect::<BTreeSet<_>>()
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let serialized =
        serde_json::to_vec(&payload.fields).map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(DecryptedGrantPayload(SecretBytes::new(serialized)))
}

fn strict_field_ids(field_ids: &[String]) -> bool {
    field_ids.windows(2).all(|pair| pair[0] < pair[1])
        && field_ids.iter().all(|field| {
            !field.is_empty()
                && field.len() <= 128
                && field.trim() == field
                && !field.bytes().any(|byte| byte.is_ascii_control())
        })
}

fn decode_32(value: &str) -> Result<[u8; 32], CryptoError> {
    decode_base64url(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)
}

fn zeroize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        serde_json::Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}
