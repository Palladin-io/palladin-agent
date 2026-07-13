//! Versioned, bounded IPC protocol for platform security brokers.
//!
//! The broker accepts complete CLI operations. It deliberately has no API-key,
//! private-key, decrypt, sign, or secret-store read verb. Secret-bearing work is
//! performed by a fixed worker owned by the broker identity.

use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_AGENT_ID_BYTES: usize = 256;
const MAX_CONSENT_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const CONSENT_DOMAIN: &[u8] = b"palladin.windows.secure-consent.v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecureOperation {
    Init,
    Doctor,
    Connect,
    Status,
    Search,
    Get,
    ReportStale,
    Agents,
    Security,
    Purge,
}

impl SecureOperation {
    fn cli_name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Doctor => "doctor",
            Self::Connect => "connect",
            Self::Status => "status",
            Self::Search => "search",
            Self::Get => "get",
            Self::ReportStale => "report-stale",
            Self::Agents => "agents",
            Self::Security => "security",
            Self::Purge => "purge",
        }
    }

    #[must_use]
    pub fn from_cli_name(name: &str) -> Option<Self> {
        match name {
            "init" => Some(Self::Init),
            "doctor" => Some(Self::Doctor),
            "connect" => Some(Self::Connect),
            "status" => Some(Self::Status),
            "search" => Some(Self::Search),
            "get" => Some(Self::Get),
            "report-stale" => Some(Self::ReportStale),
            "agents" => Some(Self::Agents),
            "security" => Some(Self::Security),
            "purge" => Some(Self::Purge),
            _ => None,
        }
    }
}

/// Resolves consent display metadata from CLI arguments. The returned profile
/// selector is not authorization: the broker-owned worker independently loads
/// the selected profile and its Agent identity.
pub fn operation_and_profile(
    arguments: &[String],
) -> Result<(SecureOperation, String), ProtocolError> {
    let mut index = 0;
    let mut profile = "default".to_owned();
    while let Some(argument) = arguments.get(index) {
        if let Some(value) = argument.strip_prefix("--id=") {
            if value.is_empty() || value.len() > MAX_AGENT_ID_BYTES {
                return Err(ProtocolError::InvalidRequest);
            }
            profile = value.to_owned();
            index = index.checked_add(1).ok_or(ProtocolError::InvalidRequest)?;
            continue;
        }
        if argument == "--id" {
            let value = arguments
                .get(index + 1)
                .filter(|value| !value.is_empty() && value.len() <= MAX_AGENT_ID_BYTES)
                .ok_or(ProtocolError::InvalidRequest)?;
            profile = value.clone();
            index = index.checked_add(2).ok_or(ProtocolError::InvalidRequest)?;
            continue;
        }
        if argument.starts_with('-') {
            return Err(ProtocolError::InvalidRequest);
        }
        let operation =
            SecureOperation::from_cli_name(argument).ok_or(ProtocolError::OperationForbidden)?;
        return Ok((operation, profile));
    }
    Err(ProtocolError::InvalidRequest)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentChallenge {
    pub nonce: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub agent_id: String,
    pub operation: SecureOperation,
    pub request_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl Drop for ConsentChallenge {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

impl std::fmt::Debug for ConsentChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsentChallenge")
            .field("nonce", &"[redacted]")
            .field("issued_at_unix_ms", &self.issued_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("agent_id", &self.agent_id)
            .field("operation", &self.operation)
            .field("request_hash", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub request_id: [u8; 16],
    pub operation: SecureOperation,
    pub arguments: Vec<String>,
    pub standard_input: Vec<u8>,
    pub consent: ConsentChallenge,
}

impl Drop for ExecuteRequest {
    fn drop(&mut self) {
        self.standard_input.zeroize();
    }
}

impl std::fmt::Debug for ExecuteRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecuteRequest")
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("arguments", &self.arguments)
            .field("standard_input", &"[redacted]")
            .field("consent", &self.consent)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ClientFrame {
    RequestChallenge {
        request_id: [u8; 16],
        operation: SecureOperation,
        /// Consent display metadata only. The worker resolves and authorizes
        /// the selected profile independently.
        agent_id: String,
        request_hash: [u8; 32],
        /// Windows Hello RSA public key returned by `RetrievePublicKey` as
        /// SPKI DER. The broker pins it to the authenticated caller SID on the
        /// first approved enrollment and rejects later key substitution.
        public_key_spki_der: Vec<u8>,
    },
    Execute(ExecuteRequest),
    Cancel {
        request_id: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputStream {
    StandardOutput,
    StandardError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BrokerFrame {
    Challenge {
        request_id: [u8; 16],
        nonce: [u8; 32],
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        agent_id: String,
        operation: SecureOperation,
        request_hash: [u8; 32],
    },
    Accepted {
        request_id: [u8; 16],
    },
    Output {
        request_id: [u8; 16],
        stream: OutputStream,
        bytes: Vec<u8>,
    },
    Exited {
        request_id: [u8; 16],
        exit_code: i32,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        code: RejectionCode,
    },
}

impl Drop for BrokerFrame {
    fn drop(&mut self) {
        if let Self::Output { bytes, .. } = self {
            bytes.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionCode {
    AuthenticationRequired,
    ConsentInvalid,
    ConsentExpired,
    ReplayDetected,
    OperationForbidden,
    InvalidRequest,
    WorkerUnavailable,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("broker frame is empty or exceeds the configured limit")]
    InvalidFrameLength,
    #[error("broker frame is malformed")]
    MalformedFrame,
    #[error("broker protocol version is unsupported")]
    UnsupportedVersion,
    #[error("broker request is invalid")]
    InvalidRequest,
    #[error("secure operation is not permitted")]
    OperationForbidden,
    #[error("operator consent is invalid")]
    ConsentInvalid,
    #[error("operator consent has expired or is not active")]
    ConsentExpired,
    #[error("operator consent was already used")]
    ReplayDetected,
    #[error("broker transport failed")]
    Transport(#[from] io::Error),
}

pub trait ConsentSignatureVerifier: Send + Sync {
    fn verify(&self, signed_payload: &[u8], signature: &[u8]) -> Result<(), ProtocolError>;
}

pub fn validate_challenge_request(
    agent_id: &str,
    public_key_spki_der: &[u8],
) -> Result<(), ProtocolError> {
    if agent_id.is_empty()
        || agent_id.len() > MAX_AGENT_ID_BYTES
        || public_key_spki_der.is_empty()
        || public_key_spki_der.len() > MAX_CONSENT_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::InvalidRequest);
    }
    // Parse now so malformed enrollment material never reaches persistent
    // broker-owned state.
    RsaPublicKey::from_public_key_der(public_key_spki_der)
        .map(|_| ())
        .map_err(|_| ProtocolError::ConsentInvalid)
}

pub struct RsaSha256ConsentVerifier {
    key: VerifyingKey<Sha256>,
}

impl RsaSha256ConsentVerifier {
    pub fn from_subject_public_key_info_der(der: &[u8]) -> Result<Self, ProtocolError> {
        let key =
            RsaPublicKey::from_public_key_der(der).map_err(|_| ProtocolError::ConsentInvalid)?;
        Ok(Self {
            key: VerifyingKey::new(key),
        })
    }
}

impl ConsentSignatureVerifier for RsaSha256ConsentVerifier {
    fn verify(&self, signed_payload: &[u8], signature: &[u8]) -> Result<(), ProtocolError> {
        let signature =
            Signature::try_from(signature).map_err(|_| ProtocolError::ConsentInvalid)?;
        self.key
            .verify(signed_payload, &signature)
            .map_err(|_| ProtocolError::ConsentInvalid)
    }
}

pub struct ReplayGuard {
    pending: BTreeMap<[u8; 32], PendingChallenge>,
    max_lifetime: Duration,
    clock_skew: Duration,
}

struct PendingChallenge {
    request_id: [u8; 16],
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    agent_id: String,
    operation: SecureOperation,
    request_hash: [u8; 32],
}

impl ReplayGuard {
    #[must_use]
    pub fn new(max_lifetime: Duration, clock_skew: Duration) -> Self {
        Self {
            pending: BTreeMap::new(),
            max_lifetime,
            clock_skew,
        }
    }

    pub fn issue_challenge(
        &mut self,
        request_id: [u8; 16],
        operation: SecureOperation,
        agent_id: String,
        request_hash: [u8; 32],
        now: SystemTime,
    ) -> Result<BrokerFrame, ProtocolError> {
        if agent_id.is_empty() || agent_id.len() > MAX_AGENT_ID_BYTES {
            return Err(ProtocolError::InvalidRequest);
        }
        let issued_at_unix_ms = unix_millis(now)?;
        let expires_at_unix_ms = issued_at_unix_ms
            .checked_add(duration_millis(self.max_lifetime)?)
            .ok_or(ProtocolError::ConsentExpired)?;
        self.pending
            .retain(|_, challenge| challenge.expires_at_unix_ms >= issued_at_unix_ms);
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ProtocolError::ConsentInvalid)?;
        if self.pending.contains_key(&nonce) {
            return Err(ProtocolError::ConsentInvalid);
        }
        self.pending.insert(
            nonce,
            PendingChallenge {
                request_id,
                issued_at_unix_ms,
                expires_at_unix_ms,
                agent_id: agent_id.clone(),
                operation,
                request_hash,
            },
        );
        Ok(BrokerFrame::Challenge {
            request_id,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            agent_id,
            operation,
            request_hash,
        })
    }

    pub fn verify_and_record(
        &mut self,
        request: &ExecuteRequest,
        verifier: &dyn ConsentSignatureVerifier,
        now: SystemTime,
    ) -> Result<(), ProtocolError> {
        validate_request(request)?;
        let now_ms = unix_millis(now)?;
        let skew_ms = duration_millis(self.clock_skew)?;
        let max_lifetime_ms = duration_millis(self.max_lifetime)?;
        let consent = &request.consent;
        // Consume before validation: invalid signatures and expired responses
        // cannot be retried, and a service restart forgets every challenge.
        let pending = self
            .pending
            .remove(&consent.nonce)
            .ok_or(ProtocolError::ReplayDetected)?;
        if consent.issued_at_unix_ms > now_ms.saturating_add(skew_ms)
            || consent.expires_at_unix_ms < now_ms
            || consent.expires_at_unix_ms < consent.issued_at_unix_ms
            || consent.expires_at_unix_ms - consent.issued_at_unix_ms > max_lifetime_ms
        {
            return Err(ProtocolError::ConsentExpired);
        }
        let expected_hash = request_hash(
            request.operation,
            &request.arguments,
            &request.standard_input,
        )?;
        if pending.request_id != request.request_id
            || pending.issued_at_unix_ms != consent.issued_at_unix_ms
            || pending.expires_at_unix_ms != consent.expires_at_unix_ms
            || pending.agent_id != consent.agent_id
            || pending.operation != consent.operation
            || pending.request_hash != consent.request_hash
            || consent.operation != request.operation
            || consent.request_hash != expected_hash
        {
            return Err(ProtocolError::ConsentInvalid);
        }
        verifier.verify(&consent_payload(consent)?, &consent.signature)?;
        Ok(())
    }
}

pub fn validate_request(request: &ExecuteRequest) -> Result<(), ProtocolError> {
    if request.arguments.is_empty()
        || request.arguments.len() > MAX_ARGUMENTS
        || request.standard_input.len() > MAX_FRAME_BYTES
        || request.consent.agent_id.is_empty()
        || request.consent.agent_id.len() > MAX_AGENT_ID_BYTES
        || request.consent.signature.is_empty()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    if request.arguments.iter().any(|argument| {
        argument.is_empty()
            || argument.len() > MAX_ARGUMENT_BYTES
            || argument.as_bytes().contains(&0)
    }) {
        return Err(ProtocolError::InvalidRequest);
    }
    if request
        .arguments
        .iter()
        .any(|argument| argument == "--host" || argument.starts_with("--host="))
    {
        // Secure host policy is broker-owned; the untrusted companion cannot
        // redirect organization authentication to an arbitrary endpoint.
        return Err(ProtocolError::OperationForbidden);
    }
    let command = command_name(&request.arguments).ok_or(ProtocolError::InvalidRequest)?;
    if matches!(command, "exec" | "inject" | "mcp") {
        return Err(ProtocolError::OperationForbidden);
    }
    if command != request.operation.cli_name() {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn command_name(arguments: &[String]) -> Option<&str> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument.starts_with("--id=") {
            if argument.len() == "--id=".len() {
                return None;
            }
            index = index.checked_add(1)?;
            continue;
        }
        if argument == "--id" {
            index = index.checked_add(2)?;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(argument);
    }
    None
}

pub fn request_hash(
    operation: SecureOperation,
    arguments: &[String],
    standard_input: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    let canonical = serde_json::to_vec(&(PROTOCOL_VERSION, operation, arguments, standard_input))
        .map_err(|_| ProtocolError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}

pub fn consent_payload(consent: &ConsentChallenge) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(&(
        PROTOCOL_VERSION,
        &consent.nonce,
        consent.issued_at_unix_ms,
        consent.expires_at_unix_ms,
        &consent.agent_id,
        consent.operation,
        &consent.request_hash,
    ))
    .map_err(|_| ProtocolError::ConsentInvalid)?;
    let mut payload = Vec::with_capacity(CONSENT_DOMAIN.len() + body.len());
    payload.extend_from_slice(CONSENT_DOMAIN);
    payload.extend_from_slice(&body);
    Ok(payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    frame: &T,
) -> Result<(), ProtocolError> {
    #[derive(Serialize)]
    struct Envelope<'a, T> {
        protocol_version: u16,
        payload: &'a T,
    }
    let mut body = serde_json::to_vec(&Envelope {
        protocol_version: PROTOCOL_VERSION,
        payload: frame,
    })
    .map_err(|_| ProtocolError::MalformedFrame)?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        body.zeroize();
        return Err(ProtocolError::InvalidFrameLength);
    }
    let length = u32::try_from(body.len()).map_err(|_| ProtocolError::InvalidFrameLength)?;
    let result = async {
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(&body).await?;
        writer.flush().await
    }
    .await;
    body.zeroize();
    result.map_err(ProtocolError::Transport)
}

pub async fn read_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, ProtocolError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrameLength);
    }
    let mut body = vec![0_u8; length];
    if let Err(error) = reader.read_exact(&mut body).await {
        body.zeroize();
        return Err(ProtocolError::Transport(error));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope<T> {
        protocol_version: u16,
        payload: T,
    }
    let result = serde_json::from_slice::<Envelope<T>>(&body)
        .map_err(|_| ProtocolError::MalformedFrame)
        .and_then(|envelope| {
            if envelope.protocol_version == PROTOCOL_VERSION {
                Ok(envelope.payload)
            } else {
                Err(ProtocolError::UnsupportedVersion)
            }
        });
    body.zeroize();
    result
}

fn unix_millis(time: SystemTime) -> Result<u64, ProtocolError> {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProtocolError::ConsentExpired)?
        .as_millis();
    u64::try_from(millis).map_err(|_| ProtocolError::ConsentExpired)
}

fn duration_millis(duration: Duration) -> Result<u64, ProtocolError> {
    u64::try_from(duration.as_millis()).map_err(|_| ProtocolError::ConsentExpired)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{SignatureEncoding, Signer};

    use super::*;

    fn signed_request(command: &str, operation: SecureOperation, nonce: u8) -> ExecuteRequest {
        let arguments = vec![command.to_owned()];
        let standard_input = b"synthetic-input".to_vec();
        let request_hash = request_hash(operation, &arguments, &standard_input).expect("hash");
        ExecuteRequest {
            request_id: [9; 16],
            operation,
            arguments,
            standard_input,
            consent: ConsentChallenge {
                nonce: [nonce; 32],
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 31_000,
                agent_id: "agent-public-id".to_owned(),
                operation,
                request_hash,
                signature: vec![1],
            },
        }
    }

    #[test]
    fn secure_v1_rejects_execution_oracles_before_worker_spawn() {
        for command in ["exec", "inject", "mcp"] {
            let request = signed_request(command, SecureOperation::Get, 1);
            assert!(matches!(
                validate_request(&request),
                Err(ProtocolError::OperationForbidden)
            ));
        }
    }

    #[test]
    fn command_and_declared_operation_must_match() {
        let request = signed_request("search", SecureOperation::Get, 1);
        assert!(matches!(
            validate_request(&request),
            Err(ProtocolError::InvalidRequest)
        ));
    }

    #[test]
    fn secure_host_cannot_be_redirected_by_the_companion() {
        let mut request = signed_request("connect", SecureOperation::Connect, 1);
        request
            .arguments
            .push("--host=https://attacker.invalid".to_owned());
        assert!(matches!(
            validate_request(&request),
            Err(ProtocolError::OperationForbidden)
        ));
    }

    #[test]
    fn rsa_consent_is_bound_to_request_and_is_single_use() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public_der = private_key
            .to_public_key()
            .to_public_key_der()
            .expect("SPKI");
        let verifier =
            RsaSha256ConsentVerifier::from_subject_public_key_info_der(public_der.as_ref())
                .expect("verifier");
        let mut request = signed_request("get", SecureOperation::Get, 7);
        let now = UNIX_EPOCH + Duration::from_millis(2_000);
        let mut replay = ReplayGuard::new(Duration::from_secs(30), Duration::from_secs(1));
        let challenge = replay
            .issue_challenge(
                request.request_id,
                request.operation,
                request.consent.agent_id.clone(),
                request.consent.request_hash,
                UNIX_EPOCH + Duration::from_millis(1_000),
            )
            .expect("challenge");
        let BrokerFrame::Challenge {
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            ..
        } = challenge
        else {
            panic!("challenge frame");
        };
        request.consent.nonce = nonce;
        request.consent.issued_at_unix_ms = issued_at_unix_ms;
        request.consent.expires_at_unix_ms = expires_at_unix_ms;
        let signing = SigningKey::<Sha256>::new(private_key);
        request.consent.signature = signing
            .sign(&consent_payload(&request.consent).expect("payload"))
            .to_vec();
        replay
            .verify_and_record(&request, &verifier, now)
            .expect("first use");
        assert!(matches!(
            replay.verify_and_record(&request, &verifier, now),
            Err(ProtocolError::ReplayDetected)
        ));
    }

    #[test]
    fn client_chosen_nonce_is_never_accepted() {
        struct AcceptAll;
        impl ConsentSignatureVerifier for AcceptAll {
            fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), ProtocolError> {
                Ok(())
            }
        }
        let request = signed_request("get", SecureOperation::Get, 42);
        let mut replay = ReplayGuard::new(Duration::from_secs(30), Duration::from_secs(1));
        assert!(matches!(
            replay.verify_and_record(
                &request,
                &AcceptAll,
                UNIX_EPOCH + Duration::from_millis(2_000)
            ),
            Err(ProtocolError::ReplayDetected)
        ));
    }

    #[test]
    fn invalid_signature_consumes_broker_nonce() {
        struct RejectAll;
        impl ConsentSignatureVerifier for RejectAll {
            fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), ProtocolError> {
                Err(ProtocolError::ConsentInvalid)
            }
        }
        let mut request = signed_request("get", SecureOperation::Get, 0);
        let issued = UNIX_EPOCH + Duration::from_millis(1_000);
        let now = UNIX_EPOCH + Duration::from_millis(2_000);
        let mut replay = ReplayGuard::new(Duration::from_secs(30), Duration::from_secs(1));
        let challenge = replay
            .issue_challenge(
                request.request_id,
                request.operation,
                request.consent.agent_id.clone(),
                request.consent.request_hash,
                issued,
            )
            .expect("challenge");
        let BrokerFrame::Challenge {
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            ..
        } = challenge
        else {
            panic!("challenge frame");
        };
        request.consent.nonce = nonce;
        request.consent.issued_at_unix_ms = issued_at_unix_ms;
        request.consent.expires_at_unix_ms = expires_at_unix_ms;
        assert!(matches!(
            replay.verify_and_record(&request, &RejectAll, now),
            Err(ProtocolError::ConsentInvalid)
        ));
        assert!(matches!(
            replay.verify_and_record(&request, &RejectAll, now),
            Err(ProtocolError::ReplayDetected)
        ));
    }

    #[test]
    fn inline_profile_selector_is_parsed_without_becoming_authorization() {
        let mut request = signed_request("get", SecureOperation::Get, 1);
        request.arguments = vec!["--id=local-profile".to_owned(), "get".to_owned()];
        assert!(validate_request(&request).is_ok());
        assert_eq!(
            operation_and_profile(&request.arguments).expect("operation"),
            (SecureOperation::Get, "local-profile".to_owned())
        );
    }

    #[test]
    fn companion_parser_rejects_execution_oracles() {
        for command in ["exec", "inject", "mcp"] {
            assert!(matches!(
                operation_and_profile(&[command.to_owned()]),
                Err(ProtocolError::OperationForbidden)
            ));
        }
    }

    #[tokio::test]
    async fn length_prefixed_frame_round_trips_without_secret_verbs() {
        let frame = ClientFrame::Cancel {
            request_id: [3; 16],
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).await.expect("write");
        let decoded: ClientFrame = read_frame(&mut bytes.as_slice()).await.expect("read");
        assert!(matches!(decoded, ClientFrame::Cancel { request_id } if request_id == [3; 16]));
        let wire = String::from_utf8(bytes).expect("UTF-8-ish frame");
        assert!(!wire.contains("api-key"));
        assert!(!wire.contains("private-key"));
        assert!(!wire.contains("read-secret"));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let mut frame = Vec::from(((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        frame.extend_from_slice(b"{}");
        let result = read_frame::<_, ClientFrame>(&mut frame.as_slice()).await;
        assert!(matches!(result, Err(ProtocolError::InvalidFrameLength)));
    }

    #[tokio::test]
    async fn unsupported_protocol_version_is_rejected() {
        let body = br#"{"protocol_version":2,"payload":{"type":"cancel","request_id":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]}}"#;
        let mut frame = Vec::from((body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        let result = read_frame::<_, ClientFrame>(&mut frame.as_slice()).await;
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion)));
    }
}
