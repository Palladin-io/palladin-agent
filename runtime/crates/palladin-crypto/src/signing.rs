use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use crate::{CryptoError, Ed25519Identity};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureHeaders {
    pub agent_id: String,
    pub timestamp: u64,
    pub nonce_base64: String,
    pub signature_base64: String,
}

#[must_use]
pub fn body_sha256_base64(body: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(body))
}

pub fn canonical_request(
    method: &str,
    path_with_query: &str,
    timestamp: u64,
    nonce_base64: &str,
    body: &[u8],
) -> Result<String, CryptoError> {
    if method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_alphabetic())
        || !path_with_query.starts_with('/')
        || path_with_query.starts_with("//")
        || path_with_query.contains(['\r', '\n'])
        || nonce_base64.contains(['\r', '\n'])
    {
        return Err(CryptoError::InvalidSigningInput);
    }

    let nonce = STANDARD
        .decode(nonce_base64)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if nonce.len() != 16 {
        return Err(CryptoError::InvalidLength);
    }

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_with_query,
        timestamp,
        nonce_base64,
        body_sha256_base64(body)
    ))
}

pub fn generate_nonce_base64() -> Result<String, CryptoError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(STANDARD.encode(nonce))
}

pub fn sign_request(
    agent_id: &str,
    identity: &Ed25519Identity,
    method: &str,
    path_with_query: &str,
    timestamp: u64,
    nonce_base64: &str,
    body: &[u8],
) -> Result<SignatureHeaders, CryptoError> {
    if agent_id.is_empty() || agent_id.contains(['\r', '\n']) {
        return Err(CryptoError::InvalidSigningInput);
    }
    let canonical = canonical_request(method, path_with_query, timestamp, nonce_base64, body)?;
    let signature = identity.sign(canonical.as_bytes());
    Ok(SignatureHeaders {
        agent_id: agent_id.to_owned(),
        timestamp,
        nonce_base64: nonce_base64.to_owned(),
        signature_base64: STANDARD.encode(signature),
    })
}
