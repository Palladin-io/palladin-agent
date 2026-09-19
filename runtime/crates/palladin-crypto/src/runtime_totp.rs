use serde_json::Value;

use crate::CryptoError;

/// Independent, versioned plaintext protocol boundary. Never returns source material.
pub fn validate_runtime_totp_source(value: &Value) -> Result<(), CryptoError> {
    let object = value.as_object().ok_or(CryptoError::InvalidDescriptor)?;
    let secret = object
        .get("secret")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidDescriptor)?;
    if object.len() != 5
        || object.get("source").and_then(Value::as_str) != Some("totp")
        || !matches!(
            object.get("algorithm").and_then(Value::as_str),
            Some("SHA1" | "SHA256" | "SHA512")
        )
        || !matches!(object.get("digits").and_then(Value::as_u64), Some(6 | 8))
        || !object
            .get("period")
            .and_then(Value::as_u64)
            .is_some_and(|period| (15..=120).contains(&period))
        || !(26..=1024).contains(&secret.len())
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let unused = match secret.len() % 8 {
        0 => 0,
        2 => 2,
        4 => 4,
        5 => 1,
        7 => 3,
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    let mut last = 0;
    for byte in secret.bytes() {
        last = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(CryptoError::InvalidDescriptor),
        };
    }
    if last & ((1 << unused) - 1) != 0 {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}
