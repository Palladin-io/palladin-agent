use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use palladin_platform::secure_store::{SecretSlot, SecretStore};
use reqwest::redirect::Policy as RedirectPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{RuntimeError, RuntimeService, integrity::TRUST_OWNER_ID};

pub const VERSION_POLICY_SOURCE: &str = "https://releases.palladin.io/agent/version-policy.json";
const POLICY_SCHEMA_VERSION: u32 = 1;
const TRUST_SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_POLICY_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;
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
        OffsetDateTime::now_utc(),
    )
}

fn verify_release_policy_candidate(
    bytes: &[u8],
    public_key: &str,
    current_version: &str,
    package_name: &str,
    source_sha: &str,
    now: OffsetDateTime,
) -> Result<(), RuntimeError> {
    let policy = verify_policy(bytes, public_key, now)?;
    if compare_versions(current_version, &policy.payload.minimum_version)?
        == std::cmp::Ordering::Less
        || policy
            .payload
            .blocked_versions
            .iter()
            .any(|blocked| blocked == current_version)
    {
        return Err(RuntimeError::VersionPolicyBlocked);
    }
    let artifact = policy.artifact(package_name, current_version)?;
    if artifact.source_sha != source_sha
        || hash_current_executable()? != artifact.worker_executable_sha256
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
    pub blocked_versions: Vec<String>,
    pub expires_at: String,
    pub issued_at: String,
    pub minimum_version: String,
    pub recommended_version: String,
    pub schema_version: u32,
    pub sequence: u64,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionPolicyEnvelope {
    signature: String,
    signed: VersionPolicyPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionPolicyTrustState {
    schema_version: u32,
    highest_sequence: u64,
    policy_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedVersionPolicy {
    pub payload: VersionPolicyPayload,
    pub digest: String,
    pub canonical_envelope: Vec<u8>,
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
    /// Verifies public candidates, advances protected anti-rollback state, then checks the runtime.
    /// No identity or organization credential is opened by this operation.
    pub fn enforce_version_policy_candidates(
        &self,
        candidates: &[Vec<u8>],
        public_key_base64: &str,
        current_version: &str,
        package_name: &str,
        source_sha: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedVersionPolicy, RuntimeError> {
        let mut verified = candidates
            .iter()
            .filter_map(|bytes| verify_policy(bytes, public_key_base64, now).ok())
            .collect::<Vec<_>>();
        verified.sort_by_key(|policy| policy.payload.sequence);
        let selected = verified.pop().ok_or(RuntimeError::VersionPolicyViolation)?;
        if verified.iter().any(|candidate| {
            candidate.payload.sequence == selected.payload.sequence
                && candidate.digest != selected.digest
        }) {
            return Err(RuntimeError::VersionPolicyViolation);
        }

        let _lock = self.repository.acquire_transaction_lock()?;
        self.persist_version_policy_cache(&selected)?;
        self.advance_version_policy_trust(&selected)?;
        let _ = prune_cache_candidates(&cache_directory(self.repository.root())?, 2);

        if compare_versions(current_version, &selected.payload.minimum_version)?
            == std::cmp::Ordering::Less
            || selected
                .payload
                .blocked_versions
                .iter()
                .any(|blocked| blocked == current_version)
        {
            return Err(RuntimeError::VersionPolicyBlocked);
        }
        let artifact = selected.artifact(package_name, current_version)?;
        if artifact.source_sha != source_sha {
            return Err(RuntimeError::VersionPolicyViolation);
        }
        Ok(selected)
    }

    pub async fn enforce_system_version_policy(
        &self,
        current_version: &str,
    ) -> Result<VerifiedVersionPolicy, RuntimeError> {
        let executable_sha256 = hash_current_executable()?;
        self.enforce_system_version_policy_for_worker_hash(current_version, &executable_sha256)
            .await
    }

    /// Enforces the signed runtime policy against an executable already opened and
    /// hashed by a native broker. The broker owns the anti-rollback state, so a
    /// caller-controlled Node process cannot authorize a different system worker.
    pub async fn enforce_system_version_policy_for_worker_hash(
        &self,
        current_version: &str,
        worker_executable_sha256: &str,
    ) -> Result<VerifiedVersionPolicy, RuntimeError> {
        let public_key = option_env!("PALLADIN_VERSION_POLICY_PUBLIC_KEY")
            .ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let source_sha =
            option_env!("SOURCE_SHA").ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let package_name =
            runtime_package_name().ok_or(RuntimeError::VersionPolicyNotConfigured)?;
        let mut candidates = self.load_version_policy_cache()?;
        if let Ok(Some(environment)) = environment_policy() {
            candidates.push(environment);
        }
        if let Ok(remote) = fetch_remote_policy().await {
            candidates.push(remote);
        }
        if let Some(bundle) = embedded_policy()? {
            candidates.push(bundle);
        }
        let policy = self.enforce_version_policy_candidates(
            &candidates,
            public_key,
            current_version,
            package_name,
            source_sha,
            OffsetDateTime::now_utc(),
        )?;
        let artifact = policy.artifact(package_name, current_version)?;
        if worker_executable_sha256 != artifact.worker_executable_sha256 {
            return Err(RuntimeError::VersionPolicyViolation);
        }
        Ok(policy)
    }

    fn advance_version_policy_trust(
        &self,
        policy: &VerifiedVersionPolicy,
    ) -> Result<(), RuntimeError> {
        let stored = self
            .secrets
            .get(TRUST_OWNER_ID, SecretSlot::VersionPolicyTrustStateV1)?
            .map(|bytes| decode_trust_state(bytes.expose_secret()))
            .transpose()?;
        if let Some(state) = stored {
            if state.highest_sequence > policy.payload.sequence
                || (state.highest_sequence == policy.payload.sequence
                    && state.policy_digest != policy.digest)
            {
                return Err(RuntimeError::VersionPolicyRollback);
            }
            if state.highest_sequence == policy.payload.sequence {
                return Ok(());
            }
        }
        let state = VersionPolicyTrustState {
            schema_version: TRUST_SCHEMA_VERSION,
            highest_sequence: policy.payload.sequence,
            policy_digest: policy.digest.clone(),
        };
        let encoded =
            serde_json::to_vec(&state).map_err(|_| RuntimeError::VersionPolicyViolation)?;
        self.secrets.set(
            TRUST_OWNER_ID,
            SecretSlot::VersionPolicyTrustStateV1,
            &encoded,
        )?;
        Ok(())
    }

    fn load_version_policy_cache(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        load_cache_candidates(&cache_directory(self.repository.root())?)
    }

    fn persist_version_policy_cache(
        &self,
        policy: &VerifiedVersionPolicy,
    ) -> Result<(), RuntimeError> {
        persist_cache_candidate(&cache_directory(self.repository.root())?, policy)
    }
}

fn verify_policy(
    bytes: &[u8],
    public_key_base64: &str,
    now: OffsetDateTime,
) -> Result<VerifiedVersionPolicy, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let envelope: VersionPolicyEnvelope =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    validate_payload(&envelope.signed, now)?;
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
    let digest = hex_digest(Sha256::digest(&canonical_envelope));
    Ok(VerifiedVersionPolicy {
        payload: envelope.signed,
        digest,
        canonical_envelope,
    })
}

fn validate_payload(
    payload: &VersionPolicyPayload,
    now: OffsetDateTime,
) -> Result<(), RuntimeError> {
    if payload.schema_version != POLICY_SCHEMA_VERSION
        || payload.sequence == 0
        || payload.sequence > MAX_SAFE_INTEGER
        || payload.source != VERSION_POLICY_SOURCE
        || parse_version(&payload.minimum_version).is_err()
        || parse_version(&payload.recommended_version).is_err()
        || compare_versions(&payload.recommended_version, &payload.minimum_version)?
            == std::cmp::Ordering::Less
        || payload
            .blocked_versions
            .iter()
            .any(|blocked| blocked == &payload.recommended_version)
        || payload.artifacts.is_empty()
        || !strictly_sorted(&payload.blocked_versions)
        || payload
            .blocked_versions
            .iter()
            .any(|version| parse_version(version).is_err())
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    let issued = parse_timestamp(&payload.issued_at)?;
    let expires = parse_timestamp(&payload.expires_at)?;
    if issued > now + time::Duration::seconds(CLOCK_SKEW_SECONDS)
        || expires <= now
        || expires <= issued
        || (expires - issued).whole_seconds() > MAX_POLICY_LIFETIME_SECONDS
    {
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

fn decode_trust_state(bytes: &[u8]) -> Result<VersionPolicyTrustState, RuntimeError> {
    let state: VersionPolicyTrustState =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::VersionPolicyViolation)?;
    if state.schema_version != TRUST_SCHEMA_VERSION
        || state.highest_sequence == 0
        || !is_lower_hex(&state.policy_digest, 64)
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    Ok(state)
}

async fn fetch_remote_policy() -> Result<Vec<u8>, RuntimeError> {
    let client = reqwest::Client::builder()
        .redirect(RedirectPolicy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    let mut response = client
        .get(VERSION_POLICY_SOURCE)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    if !response.status().is_success()
        || response.url().as_str() != VERSION_POLICY_SOURCE
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            != Some("application/json")
        || response
            .content_length()
            .is_some_and(|length| length > MAX_POLICY_BYTES as u64)
    {
        return Err(RuntimeError::VersionPolicyUnavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RuntimeError::VersionPolicyUnavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_POLICY_BYTES {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(RuntimeError::VersionPolicyUnavailable);
    }
    Ok(bytes)
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

fn cache_directory(root: &Path) -> Result<PathBuf, RuntimeError> {
    let parent = root
        .parent()
        .ok_or(RuntimeError::VersionPolicyUnavailable)?;
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RuntimeError::VersionPolicyUnavailable)?;
    Ok(parent.join(format!(".{name}.palladin-policy-cache-v1")))
}

fn load_cache_candidates(directory: &Path) -> Result<Vec<Vec<u8>>, RuntimeError> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Err(RuntimeError::VersionPolicyUnavailable),
    }
    let mut candidates = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)? {
        let entry = entry.map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if valid_cache_temporary_name(&name) {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(RuntimeError::VersionPolicyUnavailable);
            }
            fs::remove_file(entry.path()).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
            continue;
        }
        if candidates.len() >= 64 || !valid_cache_file_name(&name) {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_POLICY_BYTES as u64
        {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(entry.path())
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        let opened = file
            .metadata()
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if !opened.file_type().is_file()
            || opened.len() == 0
            || opened.len() > MAX_POLICY_BYTES as u64
        {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take((MAX_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        candidates.push(bytes);
    }
    Ok(candidates)
}

fn persist_cache_candidate(
    directory: &Path,
    policy: &VerifiedVersionPolicy,
) -> Result<(), RuntimeError> {
    ensure_cache_directory(directory)?;
    let path = directory.join(format!(
        "{}-{}.json",
        policy.payload.sequence, policy.digest
    ));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let existing = fs::read(&path).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
            if existing == policy.canonical_envelope {
                return Ok(());
            }
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(RuntimeError::VersionPolicyUnavailable),
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    let temporary = directory.join(format!(".{}.tmp", hex_digest(random)));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    let result = (|| {
        file.write_all(&policy.canonical_envelope)
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        file.sync_all()
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        drop(file);
        fs::rename(&temporary, &path).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn prune_cache_candidates(directory: &Path, retain: usize) -> Result<(), RuntimeError> {
    if retain == 0 {
        return Err(RuntimeError::VersionPolicyUnavailable);
    }
    let mut candidates = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)? {
        let entry = entry.map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if !valid_cache_file_name(&name) {
            continue;
        }
        let sequence = name
            .split_once('-')
            .and_then(|(value, _)| value.parse::<u64>().ok())
            .filter(|value| *value <= MAX_SAFE_INTEGER)
            .ok_or(RuntimeError::VersionPolicyUnavailable)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        candidates.push((sequence, name, entry.path()));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let remove = candidates.len().saturating_sub(retain);
    for (_, _, path) in candidates.into_iter().take(remove) {
        fs::remove_file(path).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    }
    if remove > 0 {
        sync_directory(directory)?;
    }
    Ok(())
}

fn ensure_cache_directory(directory: &Path) -> Result<(), RuntimeError> {
    let parent = directory
        .parent()
        .ok_or(RuntimeError::VersionPolicyUnavailable)?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Err(RuntimeError::VersionPolicyUnavailable),
    }
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder
                .create(directory)
                .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
            sync_directory(parent)
        }
        _ => Err(RuntimeError::VersionPolicyUnavailable),
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), RuntimeError> {
    let file = fs::File::open(directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    file.sync_all()
        .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

fn valid_cache_file_name(value: &str) -> bool {
    let Some((sequence, digest_json)) = value.split_once('-') else {
        return false;
    };
    let Some(digest) = digest_json.strip_suffix(".json") else {
        return false;
    };
    !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && !sequence.starts_with('0')
        && is_lower_hex(digest, 64)
}

fn valid_cache_temporary_name(value: &str) -> bool {
    value
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
        .is_some_and(|digest| is_lower_hex(digest, 32))
}

pub(crate) fn purge_version_policy_cache(root: &Path) -> Result<(), RuntimeError> {
    let directory = cache_directory(root)?;
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Err(RuntimeError::VersionPolicyUnavailable),
    }
    for entry in fs::read_dir(&directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)? {
        let entry = entry.map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !valid_cache_file_name(&name) && !valid_cache_temporary_name(&name) {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(RuntimeError::VersionPolicyUnavailable);
        }
    }
    for entry in fs::read_dir(&directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)? {
        let entry = entry.map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
        fs::remove_file(entry.path()).map_err(|_| RuntimeError::VersionPolicyUnavailable)?;
    }
    fs::remove_dir(directory).map_err(|_| RuntimeError::VersionPolicyUnavailable)
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
    let path = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let path = std::env::current_exe().map_err(|_| RuntimeError::VersionPolicyViolation)?;
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| RuntimeError::VersionPolicyViolation)?;
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

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, RuntimeError> {
    if value.len() != 20
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'Z')
    {
        return Err(RuntimeError::VersionPolicyViolation);
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| RuntimeError::VersionPolicyViolation)
}

fn compare_versions(left: &str, right: &str) -> Result<std::cmp::Ordering, RuntimeError> {
    Ok(parse_version(left)?.cmp(&parse_version(right)?))
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
    value == "@palladin/agent"
        || value
            .strip_prefix("@palladin/runtime-")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left < right)
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

use secrecy::ExposeSecret;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer, SigningKey};
    use palladin_core::profiles::ProfileRepository;
    use palladin_platform::secure_store::{SecretSlot, StoreError};

    use super::*;

    const SOURCE_SHA: &str = "1234567890abcdef1234567890abcdef12345678";
    const PACKAGE: &str = "@palladin/runtime-linux-x64-gnu";

    type StoredValues = BTreeMap<(String, SecretSlot), Vec<u8>>;

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<StoredValues>>);

    impl SecretStore for MemoryStore {
        fn get(
            &self,
            owner_id: &str,
            slot: SecretSlot,
        ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("store")
                .get(&(owner_id.to_owned(), slot))
                .cloned()
                .map(Into::into))
        }

        fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("store")
                .insert((owner_id.to_owned(), slot), secret.to_vec());
            Ok(())
        }

        fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("store")
                .remove(&(owner_id.to_owned(), slot));
            Ok(())
        }
    }

    struct Fixture {
        service: RuntimeService<MemoryStore>,
        store: MemoryStore,
        root: PathBuf,
        signing: SigningKey,
        public_key: String,
        _directory: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temp");
        let root = directory.path().join("profiles");
        std::fs::create_dir(&root).expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("permissions");
        }
        let repository = ProfileRepository::new(root.clone()).expect("repository");
        let store = MemoryStore::default();
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).expect("random signing fixture");
        let signing = SigningKey::from_bytes(&secret);
        let public_key = STANDARD.encode(signing.verifying_key().to_bytes());
        Fixture {
            service: RuntimeService::new(repository, store.clone()),
            store,
            root,
            signing,
            public_key,
            _directory: directory,
        }
    }

    fn payload(sequence: u64) -> VersionPolicyPayload {
        VersionPolicyPayload {
            artifacts: vec![VersionPolicyArtifact {
                authenticode_publisher: None,
                authenticode_thumbprint: None,
                executable_sha256: "11".repeat(32),
                package_name: PACKAGE.to_owned(),
                source_sha: SOURCE_SHA.to_owned(),
                version: "0.1.2".to_owned(),
                worker_executable_sha256: "22".repeat(32),
            }],
            blocked_versions: vec!["0.1.1".to_owned()],
            expires_at: "2026-07-21T11:55:00Z".to_owned(),
            issued_at: "2026-07-14T11:55:00Z".to_owned(),
            minimum_version: "0.1.0".to_owned(),
            recommended_version: "0.1.2".to_owned(),
            schema_version: 1,
            sequence,
            source: VERSION_POLICY_SOURCE.to_owned(),
        }
    }

    fn sign_policy(payload: VersionPolicyPayload, signing: &SigningKey) -> Vec<u8> {
        let canonical = serde_json::to_vec(&payload).expect("payload");
        let signature = signing.sign(&canonical);
        serde_json::to_vec(&VersionPolicyEnvelope {
            signature: STANDARD.encode(signature.to_bytes()),
            signed: payload,
        })
        .expect("envelope")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-14T12:00:00Z", &Rfc3339).expect("now")
    }

    #[test]
    fn signed_policy_advances_native_secure_sequence_before_identity_can_open() {
        let fixture = fixture();
        let bytes = sign_policy(payload(7), &fixture.signing);
        let verified = fixture
            .service
            .enforce_version_policy_candidates(
                &[bytes],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now(),
            )
            .expect("policy");
        assert_eq!(verified.payload.sequence, 7);
        assert_eq!(
            verified
                .artifact(PACKAGE, "0.1.2")
                .expect("artifact")
                .source_sha,
            SOURCE_SHA
        );
        assert!(
            fixture
                .service
                .secrets
                .get(TRUST_OWNER_ID, SecretSlot::VersionPolicyTrustStateV1)
                .expect("trust")
                .is_some()
        );
    }

    #[test]
    fn release_candidate_binds_the_exact_running_worker_without_secret_state() {
        let fixture = fixture();
        let mut candidate = payload(7);
        candidate.artifacts[0].worker_executable_sha256 =
            hash_current_executable().expect("test executable hash");
        let bytes = sign_policy(candidate.clone(), &fixture.signing);
        verify_release_policy_candidate(
            &bytes,
            &fixture.public_key,
            "0.1.2",
            PACKAGE,
            SOURCE_SHA,
            now(),
        )
        .expect("candidate");

        candidate.artifacts[0].worker_executable_sha256 = "ff".repeat(32);
        let mismatched = sign_policy(candidate, &fixture.signing);
        assert!(matches!(
            verify_release_policy_candidate(
                &mismatched,
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now(),
            ),
            Err(RuntimeError::VersionPolicyViolation)
        ));
    }

    #[test]
    fn protected_state_rejects_replay_and_same_sequence_mix_and_match() {
        let fixture = fixture();
        let current = sign_policy(payload(7), &fixture.signing);
        fixture
            .service
            .enforce_version_policy_candidates(
                std::slice::from_ref(&current),
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now(),
            )
            .expect("current");

        let replay = sign_policy(payload(6), &fixture.signing);
        assert!(matches!(
            fixture.service.enforce_version_policy_candidates(
                &[replay],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now()
            ),
            Err(RuntimeError::VersionPolicyRollback)
        ));

        let mut conflicting = payload(7);
        conflicting.expires_at = "2026-07-22T11:55:00Z".to_owned();
        let conflicting = sign_policy(conflicting, &fixture.signing);
        assert!(matches!(
            fixture.service.enforce_version_policy_candidates(
                &[current, conflicting],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now()
            ),
            Err(RuntimeError::VersionPolicyViolation)
        ));
    }

    #[test]
    fn blocked_policy_is_remembered_before_returning_without_opening_identity() {
        let fixture = fixture();
        let mut blocked = payload(8);
        blocked.blocked_versions.push("0.1.2".to_owned());
        blocked.recommended_version = "0.1.0".to_owned();
        let blocked = sign_policy(blocked, &fixture.signing);
        assert!(matches!(
            fixture.service.enforce_version_policy_candidates(
                &[blocked],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now()
            ),
            Err(RuntimeError::VersionPolicyBlocked)
        ));
        let older = sign_policy(payload(7), &fixture.signing);
        assert!(matches!(
            fixture.service.enforce_version_policy_candidates(
                &[older],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now()
            ),
            Err(RuntimeError::VersionPolicyRollback)
        ));
    }

    #[test]
    fn higher_online_sequence_is_atomic_public_cache_for_the_next_offline_restart() {
        let fixture = fixture();
        for sequence in [7, 8, 9] {
            let policy = sign_policy(payload(sequence), &fixture.signing);
            fixture
                .service
                .enforce_version_policy_candidates(
                    &[policy],
                    &fixture.public_key,
                    "0.1.2",
                    PACKAGE,
                    SOURCE_SHA,
                    now(),
                )
                .expect("online policy");
        }
        let cache_directory = cache_directory(&fixture.root).expect("cache directory");
        assert_eq!(
            std::fs::read_dir(&cache_directory)
                .expect("cache entries")
                .count(),
            2
        );
        std::fs::write(
            cache_directory.join(format!(".{}.tmp", "aa".repeat(16))),
            b"crash residue",
        )
        .expect("orphan temporary cache file");

        let restarted = RuntimeService::new(
            ProfileRepository::new(fixture.root.clone()).expect("repository"),
            fixture.store.clone(),
        );
        let cached = restarted.load_version_policy_cache().expect("public cache");
        let verified = restarted
            .enforce_version_policy_candidates(
                &cached,
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now(),
            )
            .expect("offline restart");
        assert_eq!(verified.payload.sequence, 9);
    }

    #[test]
    fn cache_persistence_failure_never_advances_protected_sequence() {
        let fixture = fixture();
        let cache = cache_directory(&fixture.root).expect("cache path");
        std::fs::write(&cache, b"not-a-directory").expect("blocking cache artifact");
        let policy = sign_policy(payload(9), &fixture.signing);
        assert!(matches!(
            fixture.service.enforce_version_policy_candidates(
                &[policy],
                &fixture.public_key,
                "0.1.2",
                PACKAGE,
                SOURCE_SHA,
                now()
            ),
            Err(RuntimeError::VersionPolicyUnavailable)
        ));
        assert!(
            fixture
                .store
                .get(TRUST_OWNER_ID, SecretSlot::VersionPolicyTrustStateV1)
                .expect("trust state")
                .is_none()
        );
    }

    #[test]
    fn numeric_domain_matches_the_javascript_safe_integer_contract() {
        let fixture = fixture();
        let oversized_sequence = sign_policy(payload(MAX_SAFE_INTEGER + 1), &fixture.signing);
        assert!(verify_policy(&oversized_sequence, &fixture.public_key, now()).is_err());

        let mut oversized_version = payload(7);
        oversized_version.minimum_version = format!("{}.0.0", MAX_SAFE_INTEGER + 1);
        let oversized_version = sign_policy(oversized_version, &fixture.signing);
        assert!(verify_policy(&oversized_version, &fixture.public_key, now()).is_err());
    }

    #[test]
    fn canonical_envelope_rejects_unknown_duplicate_and_tampered_json() {
        let fixture = fixture();
        let valid = sign_policy(payload(7), &fixture.signing);
        let mut unknown: serde_json::Value = serde_json::from_slice(&valid).expect("json");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("attacker".to_owned(), serde_json::Value::Bool(true));
        let unknown = serde_json::to_vec(&unknown).expect("unknown");
        let duplicate = String::from_utf8(valid.clone())
            .expect("utf8")
            .replacen(
                "{\"signature\":",
                "{\"signature\":\"invalid\",\"signature\":",
                1,
            )
            .into_bytes();
        let mut tampered = valid;
        let index = tampered
            .windows(b"0.1.2".len())
            .position(|window| window == b"0.1.2")
            .expect("version");
        tampered[index + 4] = b'3';
        for bytes in [unknown, duplicate, tampered] {
            assert!(verify_policy(&bytes, &fixture.public_key, now()).is_err());
        }
    }
}
