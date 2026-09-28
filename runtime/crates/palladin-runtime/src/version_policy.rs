use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use palladin_platform::secure_store::SecretStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{RuntimeError, RuntimeService};

const POLICY_SCHEMA_VERSION: u32 = 2;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Release-only gate for a public candidate file. It never opens profile or secret state.
pub fn verify_release_policy_file(path: &Path, current_version: &str) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_POLICY_BYTES as u64
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let bytes = fs::read(path).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    let public_key = option_env!("PALLADIN_VERSION_POLICY_PUBLIC_KEY")
        .ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    let source_sha = option_env!("SOURCE_SHA").ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    let package_name = runtime_package_name().ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    verify_release_policy_candidate(
        &bytes,
        public_key,
        current_version,
        package_name,
        source_sha,
    )
}

/// Verifies the public policy forwarded by the npm dispatcher against worker
/// bytes that a native launcher has already copied into an immutable image.
/// This gate does not open profile or secret state.
pub fn verify_environment_policy_for_worker_hash(
    current_version: &str,
    worker_executable_sha256: &str,
) -> Result<(), RuntimeError> {
    let bytes = environment_policy()?.ok_or(RuntimeError::VersionPolicyUnavailable)?;
    verify_manifest_for_worker_hash(&bytes, current_version, worker_executable_sha256).map(|_| ())
}

pub fn verify_manifest_for_worker_hash(
    bytes: &[u8],
    current_version: &str,
    worker_executable_sha256: &str,
) -> Result<String, RuntimeError> {
    let public_key = option_env!("PALLADIN_VERSION_POLICY_PUBLIC_KEY")
        .ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    let source_sha = option_env!("SOURCE_SHA").ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    let package_name = runtime_package_name().ok_or(RuntimeError::VersionPolicyNotConfigured)?;
    verify_release_policy_candidate_for_worker_hash(
        bytes,
        public_key,
        current_version,
        package_name,
        source_sha,
        worker_executable_sha256,
    )?;
    Ok(STANDARD.encode(bytes))
}

fn verify_release_policy_candidate(
    bytes: &[u8],
    public_key: &str,
    current_version: &str,
    package_name: &str,
    source_sha: &str,
) -> Result<(), RuntimeError> {
    let worker_executable_sha256 = hash_current_executable()?;
    verify_release_policy_candidate_for_worker_hash(
        bytes,
        public_key,
        current_version,
        package_name,
        source_sha,
        &worker_executable_sha256,
    )
}

fn verify_release_policy_candidate_for_worker_hash(
    bytes: &[u8],
    public_key: &str,
    current_version: &str,
    package_name: &str,
    source_sha: &str,
    worker_executable_sha256: &str,
) -> Result<(), RuntimeError> {
    let policy = verify_policy(bytes, public_key)?;
    let artifact = policy.artifact(package_name, current_version)?;
    if artifact.source_sha != source_sha
        || worker_executable_sha256 != artifact.worker_executable_sha256
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    Ok(())
}

#[must_use]
pub fn system_version_policy_configured() -> bool {
    option_env!("PALLADIN_VERSION_POLICY_PUBLIC_KEY").is_some_and(|key| {
        decode_base64_exact::<32>(key).is_ok_and(|bytes| bytes.iter().any(|byte| *byte != 0))
    }) && option_env!("SOURCE_SHA").is_some_and(|sha| is_lower_hex(sha, 40))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionPolicyArtifact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode_publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode_thumbprint: Option<String>,
    pub executable_sha256: String,
    pub package_name: String,
    pub source_sha: String,
    pub version: String,
    pub worker_executable_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionPolicyPayload {
    pub artifacts: Vec<VersionPolicyArtifact>,
    pub schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionPolicyEnvelope {
    signature: String,
    signed: VersionPolicyPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedVersionPolicy {
    pub payload: VersionPolicyPayload,
}

impl VerifiedVersionPolicy {
    pub fn artifact(
        &self,
        package_name: &str,
        version: &str,
    ) -> Result<&VersionPolicyArtifact, RuntimeError> {
        let matches = self
            .payload
            .artifacts
            .iter()
            .filter(|artifact| artifact.package_name == package_name && artifact.version == version)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(RuntimeError::VersionPolicyViolation);
        }
        Ok(matches[0])
    }
}

impl<S: SecretStore> RuntimeService<S> {
    pub fn enforce_system_version_policy(&self, current_version: &str) -> Result<(), RuntimeError> {
        let executable_sha256 = hash_current_executable()?;
        self.enforce_system_version_policy_for_worker_hash(current_version, &executable_sha256)
    }

    /// Native code verifies the actual image independently of the npm dispatcher.
    /// This operation never accesses identity, a clock, a network endpoint or persistent policy state.
    pub fn enforce_system_version_policy_for_worker_hash(
        &self,
        current_version: &str,
        worker_executable_sha256: &str,
    ) -> Result<(), RuntimeError> {
        let public_key = option_env!("PALLADIN_VERSION_POLICY_PUBLIC_KEY")
            .ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let source_sha =
            option_env!("SOURCE_SHA").ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let package_name =
            runtime_package_name().ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let manifest = environment_policy()?.or(embedded_policy()?);
        let Some(bytes) = manifest else {
            // A directly launched macOS app is authenticated by Developer ID and the
            // provisioned Data Protection Keychain boundary before this call. Linux
            // must receive an independently signed manifest for its exact worker.
            if cfg!(target_os = "macos") {
                return Ok(());
            }
            return Err(RuntimeError::VersionPolicyUnavailable);
        };
        verify_release_policy_candidate_for_worker_hash(
            &bytes,
            public_key,
            current_version,
            package_name,
            source_sha,
            worker_executable_sha256,
        )
    }
}

fn verify_policy(
    bytes: &[u8],
    public_key_base64: &str,
) -> Result<VerifiedVersionPolicy, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let envelope: VersionPolicyEnvelope =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    validate_payload(&envelope.signed)?;
    let canonical_envelope =
        serde_json::to_vec(&envelope).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if canonical_envelope != bytes {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let canonical_payload =
        serde_json::to_vec(&envelope.signed).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    let public_key = decode_base64_exact::<32>(public_key_base64)?;
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(RuntimeError::VersionPolicyNotConfigured);
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    let signature = Signature::from_bytes(&decode_base64_exact::<64>(&envelope.signature)?);
    verifying_key
        .verify(&canonical_payload, &signature)
        .map_err(|_| RuntimeError::VersionPolicyViolation)?;
    Ok(VerifiedVersionPolicy {
        payload: envelope.signed,
    })
}

fn validate_payload(payload: &VersionPolicyPayload) -> Result<(), RuntimeError> {
    if payload.schema_version != POLICY_SCHEMA_VERSION || payload.artifacts.is_empty() {
        return Err(RuntimeError::VersionPolicyViolation);
    }

    let mut identities = BTreeSet::new();
    let mut previous = None::<String>;
    for artifact in &payload.artifacts {
        let identity = format!("{}@{}", artifact.package_name, artifact.version);
        if previous.as_ref().is_some_and(|value| value >= &identity)
            || !identities.insert(identity.clone())
            || !valid_package_name(&artifact.package_name)
            || parse_version(&artifact.version).is_err()
            || !is_lower_hex(&artifact.source_sha, 40)
            || artifact.source_sha.bytes().all(|byte| byte == b'0')
            || !is_lower_hex(&artifact.executable_sha256, 64)
            || !is_lower_hex(&artifact.worker_executable_sha256, 64)
        {
            return Err(RuntimeError::VersionPolicyViolation);
        }
        previous = Some(identity);
        let windows = artifact
            .package_name
            .starts_with("@palladin/runtime-win32-");
        match (
            windows,
            &artifact.authenticode_publisher,
            &artifact.authenticode_thumbprint,
        ) {
            (false, None, None) => {}
            (true, Some(publisher), Some(thumbprint))
                if !publisher.is_empty()
                    && publisher.len() <= 256
                    && publisher.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                    && ((thumbprint.len() == 40 || thumbprint.len() == 64)
                        && thumbprint.bytes().all(|byte| {
                            byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
                        })) => {}
            _ => return Err(RuntimeError::VersionPolicyViolation),
        }
    }
    Ok(())
}

fn embedded_policy() -> Result<Option<Vec<u8>>, RuntimeError> {
    let Some(encoded) = option_env!("PALLADIN_VERSION_POLICY_BUNDLE_BASE64") else {
        return Ok(None);
    };
    if encoded.is_empty() {
        return Ok(None);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| RuntimeError::VersionPolicyNotConfigured)?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || STANDARD.encode(&bytes) != encoded {
        return Err(RuntimeError::VersionPolicyNotConfigured);
    }
    Ok(Some(bytes))
}

fn environment_policy() -> Result<Option<Vec<u8>>, RuntimeError> {
    let Some(encoded) = std::env::var_os("PALLADIN_VERSION_POLICY_ENVELOPE_BASE64") else {
        return Ok(None);
    };
    let encoded = encoded
        .into_string()
        .map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if encoded.is_empty() || encoded.len() > (MAX_POLICY_BYTES * 4 / 3) + 4 {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let bytes = STANDARD
        .decode(&encoded)
        .map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES || STANDARD.encode(&bytes) != encoded {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    Ok(Some(bytes))
}

fn runtime_package_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("@palladin/runtime-darwin-arm64"),
        ("macos", "x86_64") => Some("@palladin/runtime-darwin-x64"),
        ("windows", "aarch64") => Some("@palladin/runtime-win32-arm64"),
        ("windows", "x86_64") => Some("@palladin/runtime-win32-x64"),
        ("linux", "aarch64") if cfg!(target_env = "musl") => {
            Some("@palladin/runtime-linux-arm64-musl")
        }
        ("linux", "aarch64") => Some("@palladin/runtime-linux-arm64-gnu"),
        ("linux", "x86_64") if cfg!(target_env = "musl") => {
            Some("@palladin/runtime-linux-x64-musl")
        }
        ("linux", "x86_64") => Some("@palladin/runtime-linux-x64-gnu"),
        _ => None,
    }
}

fn hash_current_executable() -> Result<String, RuntimeError> {
    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    let path = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let path = std::env::current_exe().map_err(|_| RuntimeError::VersionPolicyViolation)?;
    #[cfg(not(target_os = "linux"))]
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    #[cfg(not(target_os = "linux"))]
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let mut file = fs::File::open(path).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let mut hasher = Sha256::new();
    let copied =
        std::io::copy(&mut file, &mut hasher).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if copied != metadata.len() {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    Ok(hex_digest(hasher.finalize()))
}

fn parse_version(value: &str) -> Result<[u64; 3], RuntimeError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || (part.len() > 1 && part.starts_with('0')))
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let parsed = [
        parts[0]
            .parse()
            .map_err(|_| RuntimeError::VersionPolicyViolation)?,
        parts[1]
            .parse()
            .map_err(|_| RuntimeError::VersionPolicyViolation)?,
        parts[2]
            .parse()
            .map_err(|_| RuntimeError::VersionPolicyViolation)?,
    ];
    if parsed.iter().any(|part| *part > MAX_SAFE_INTEGER) {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    Ok(parsed)
}

fn decode_base64_exact<const N: usize>(value: &str) -> Result<[u8; N], RuntimeError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if bytes.len() != N || STANDARD.encode(&bytes) != value {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    bytes
        .try_into()
        .map_err(|_| RuntimeError::VersionPolicyViolation)
}

fn valid_package_name(value: &str) -> bool {
    value == "@palladin/cli"
        || value
            .strip_prefix("@palladin/runtime-")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SOURCE: &str = "1234567890abcdef1234567890abcdef12345678";
    const PACKAGE: &str = "@palladin/runtime-linux-x64-gnu";

    fn fixture() -> (Vec<u8>, String) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let payload = VersionPolicyPayload {
            schema_version: 2,
            artifacts: vec![VersionPolicyArtifact {
                authenticode_publisher: None,
                authenticode_thumbprint: None,
                executable_sha256: "11".repeat(32),
                worker_executable_sha256: "22".repeat(32),
                package_name: PACKAGE.to_owned(),
                version: "0.0.1".to_owned(),
                source_sha: SOURCE.to_owned(),
            }],
        };
        let signature = STANDARD.encode(
            signing
                .sign(&serde_json::to_vec(&payload).expect("payload"))
                .to_bytes(),
        );
        (
            serde_json::to_vec(&VersionPolicyEnvelope {
                signature,
                signed: payload,
            })
            .expect("envelope"),
            STANDARD.encode(signing.verifying_key().to_bytes()),
        )
    }

    #[test]
    fn signed_release_binds_exact_native_image_without_time_or_online_state() {
        let (bytes, key) = fixture();
        assert!(
            verify_release_policy_candidate_for_worker_hash(
                &bytes,
                &key,
                "0.0.1",
                PACKAGE,
                SOURCE,
                &"22".repeat(32),
            )
            .is_ok()
        );
        for (version, package, source, hash) in [
            ("0.0.2", PACKAGE, SOURCE, "22".repeat(32)),
            (
                "0.0.1",
                "@palladin/runtime-linux-arm64-gnu",
                SOURCE,
                "22".repeat(32),
            ),
            (
                "0.0.1",
                PACKAGE,
                "abcdef1234567890abcdef1234567890abcdef12",
                "22".repeat(32),
            ),
            ("0.0.1", PACKAGE, SOURCE, "33".repeat(32)),
        ] {
            assert!(
                verify_release_policy_candidate_for_worker_hash(
                    &bytes, &key, version, package, source, &hash
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_tampering_wrong_signer_unknown_fields_and_legacy_online_policy() {
        let (bytes, key) = fixture();
        let wrong_key =
            STANDARD.encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert!(verify_policy(&bytes, &wrong_key).is_err());
        let mut envelope: VersionPolicyEnvelope = serde_json::from_slice(&bytes).expect("envelope");
        envelope.signed.artifacts[0].worker_executable_sha256 = "33".repeat(32);
        assert!(verify_policy(&serde_json::to_vec(&envelope).expect("changed"), &key).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("value");
        value["signed"]["expiresAt"] = "2099-01-01T00:00:00Z".into();
        assert!(verify_policy(&serde_json::to_vec(&value).expect("unknown"), &key).is_err());
        assert!(verify_policy(&vec![0; MAX_POLICY_BYTES + 1], &key).is_err());
    }
}
