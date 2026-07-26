use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    ALGORITHM_SUITE, CryptoError, PROTOCOL_VERSION, SecretBytes, SignatureProfile,
    decode_base64url, key_fingerprint, verify_domain_signature,
};

const PAIRING_DOMAIN: &[u8] = b"PLDNV2PAIR:TRANSCRIPT:";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultManifestV2 {
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub organization_id: String,
    pub vault_id: String,
    pub agent_id: String,
    pub agent_x25519_fingerprint: String,
    pub agent_ed25519_fingerprint: String,
    pub vault_signing_public_key: String,
    pub vault_signing_key_fingerprint: String,
    pub manifest_signing_key_version: u32,
    pub vault_agent_message_public_key: String,
    pub vault_agent_message_key_fingerprint: String,
    pub agent_message_key_version: u32,
    pub vdk_version: u32,
    pub agent_wrapped_vdk_digest: String,
    pub manifest_revision: String,
    pub issued_at: String,
    pub minimum_agent_runtime_protocol: u16,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentityBinding {
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub x25519_fingerprint: [u8; 32],
    pub ed25519_fingerprint: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingVault {
    pub manifest_revision: String,
    pub signed_manifest_digest: String,
    pub vault_id: String,
    pub vault_signing_key_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingTranscript {
    pub activation_id: String,
    pub agent_ed25519_fingerprint: String,
    pub agent_id: String,
    pub agent_x25519_fingerprint: String,
    pub algorithm_suite: u16,
    pub organization_id: String,
    pub protocol_version: u16,
    pub vaults: Vec<PairingVault>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedVaultTrust {
    pub vault_id: Uuid,
    pub signing_public_key: [u8; 32],
    pub signing_key_fingerprint: [u8; 32],
    pub manifest_revision: u64,
    pub manifest_signing_key_version: u32,
}

#[derive(Debug)]
pub struct PairingCandidate {
    transcript: PairingTranscript,
    transcript_digest: String,
    sas: String,
    anchors: Vec<PinnedVaultTrust>,
}

impl PairingCandidate {
    #[must_use]
    pub fn transcript(&self) -> &PairingTranscript {
        &self.transcript
    }

    #[must_use]
    pub fn short_authentication_string(&self) -> &str {
        &self.sas
    }

    #[must_use]
    pub fn transcript_digest(&self) -> &str {
        &self.transcript_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberPairingConfirmation {
    /// Digest constructed by an independently trusted, unlocked Member client.
    pub transcript_digest: String,
    pub short_authentication_string: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingRelayStatus {
    pub activation_id: String,
    pub status: String,
    pub expires_at: String,
    pub confirmed_pairing_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedManifest<'a> {
    agent_ed25519_fingerprint: &'a str,
    agent_id: &'a str,
    agent_message_key_version: u32,
    agent_wrapped_vdk_digest: &'a str,
    agent_x25519_fingerprint: &'a str,
    algorithm_suite: u16,
    issued_at: &'a str,
    manifest_revision: &'a str,
    manifest_signing_key_version: u32,
    minimum_agent_runtime_protocol: u16,
    organization_id: &'a str,
    protocol_version: u16,
    vault_agent_message_key_fingerprint: &'a str,
    vault_agent_message_public_key: &'a str,
    vault_id: &'a str,
    vault_signing_key_fingerprint: &'a str,
    vault_signing_public_key: &'a str,
    vdk_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedManifest<'a> {
    agent_ed25519_fingerprint: &'a str,
    agent_id: &'a str,
    agent_message_key_version: u32,
    agent_wrapped_vdk_digest: &'a str,
    agent_x25519_fingerprint: &'a str,
    algorithm_suite: u16,
    issued_at: &'a str,
    manifest_revision: &'a str,
    manifest_signing_key_version: u32,
    minimum_agent_runtime_protocol: u16,
    organization_id: &'a str,
    protocol_version: u16,
    signature: &'a str,
    vault_agent_message_key_fingerprint: &'a str,
    vault_agent_message_public_key: &'a str,
    vault_id: &'a str,
    vault_signing_key_fingerprint: &'a str,
    vault_signing_public_key: &'a str,
    vdk_version: u32,
}

fn unsigned_manifest(manifest: &VaultManifestV2) -> UnsignedManifest<'_> {
    UnsignedManifest {
        agent_ed25519_fingerprint: &manifest.agent_ed25519_fingerprint,
        agent_id: &manifest.agent_id,
        agent_message_key_version: manifest.agent_message_key_version,
        agent_wrapped_vdk_digest: &manifest.agent_wrapped_vdk_digest,
        agent_x25519_fingerprint: &manifest.agent_x25519_fingerprint,
        algorithm_suite: manifest.algorithm_suite,
        issued_at: &manifest.issued_at,
        manifest_revision: &manifest.manifest_revision,
        manifest_signing_key_version: manifest.manifest_signing_key_version,
        minimum_agent_runtime_protocol: manifest.minimum_agent_runtime_protocol,
        organization_id: &manifest.organization_id,
        protocol_version: manifest.protocol_version,
        vault_agent_message_key_fingerprint: &manifest.vault_agent_message_key_fingerprint,
        vault_agent_message_public_key: &manifest.vault_agent_message_public_key,
        vault_id: &manifest.vault_id,
        vault_signing_key_fingerprint: &manifest.vault_signing_key_fingerprint,
        vault_signing_public_key: &manifest.vault_signing_public_key,
        vdk_version: manifest.vdk_version,
    }
}

fn signed_manifest(manifest: &VaultManifestV2) -> SignedManifest<'_> {
    let unsigned = unsigned_manifest(manifest);
    SignedManifest {
        agent_ed25519_fingerprint: unsigned.agent_ed25519_fingerprint,
        agent_id: unsigned.agent_id,
        agent_message_key_version: unsigned.agent_message_key_version,
        agent_wrapped_vdk_digest: unsigned.agent_wrapped_vdk_digest,
        agent_x25519_fingerprint: unsigned.agent_x25519_fingerprint,
        algorithm_suite: unsigned.algorithm_suite,
        issued_at: unsigned.issued_at,
        manifest_revision: unsigned.manifest_revision,
        manifest_signing_key_version: unsigned.manifest_signing_key_version,
        minimum_agent_runtime_protocol: unsigned.minimum_agent_runtime_protocol,
        organization_id: unsigned.organization_id,
        protocol_version: unsigned.protocol_version,
        signature: &manifest.signature,
        vault_agent_message_key_fingerprint: unsigned.vault_agent_message_key_fingerprint,
        vault_agent_message_public_key: unsigned.vault_agent_message_public_key,
        vault_id: unsigned.vault_id,
        vault_signing_key_fingerprint: unsigned.vault_signing_key_fingerprint,
        vault_signing_public_key: unsigned.vault_signing_public_key,
        vdk_version: unsigned.vdk_version,
    }
}

fn decode_32(value: &str) -> Result<[u8; 32], CryptoError> {
    decode_base64url(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)
}

fn parse_revision(value: &str) -> Result<u64, CryptoError> {
    let revision: u64 = value.parse().map_err(|_| CryptoError::InvalidEncoding)?;
    if revision == 0 || value != revision.to_string() {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(revision)
}

fn validate_identity(
    manifest: &VaultManifestV2,
    identity: &AgentIdentityBinding,
) -> Result<(), CryptoError> {
    if manifest.protocol_version != PROTOCOL_VERSION
        || manifest.algorithm_suite != ALGORITHM_SUITE
        || manifest.minimum_agent_runtime_protocol > PROTOCOL_VERSION
        || manifest.organization_id != identity.organization_id.to_string()
        || manifest.agent_id != identity.agent_id.to_string()
        || decode_32(&manifest.agent_x25519_fingerprint)? != identity.x25519_fingerprint
        || decode_32(&manifest.agent_ed25519_fingerprint)? != identity.ed25519_fingerprint
        || manifest.vdk_version == 0
        || manifest.agent_message_key_version == 0
        || manifest.manifest_signing_key_version == 0
    {
        return Err(CryptoError::InvalidProfile);
    }
    parse_revision(&manifest.manifest_revision)?;
    Ok(())
}

pub fn prepare_pairing(
    activation_id: Uuid,
    identity: &AgentIdentityBinding,
    manifests: &[VaultManifestV2],
) -> Result<PairingCandidate, CryptoError> {
    if manifests.is_empty() {
        return Err(CryptoError::InvalidProfile);
    }
    let mut vaults = Vec::with_capacity(manifests.len());
    let mut anchors = Vec::with_capacity(manifests.len());
    let mut seen = BTreeSet::new();
    let mut previous_vault_id: Option<[u8; 16]> = None;
    for manifest in manifests {
        validate_identity(manifest, identity)?;
        let vault_id =
            Uuid::parse_str(&manifest.vault_id).map_err(|_| CryptoError::InvalidEncoding)?;
        let vault_id_bytes = *vault_id.as_bytes();
        if previous_vault_id.is_some_and(|previous| previous >= vault_id_bytes)
            || !seen.insert(vault_id_bytes)
        {
            return Err(CryptoError::InvalidProfile);
        }
        previous_vault_id = Some(vault_id_bytes);
        let signing_public_key = decode_32(&manifest.vault_signing_public_key)?;
        let signing_key_fingerprint = decode_32(&manifest.vault_signing_key_fingerprint)?;
        if key_fingerprint(3, &signing_public_key)? != signing_key_fingerprint {
            return Err(CryptoError::AuthenticationFailed);
        }
        let signed_bytes = serde_json::to_vec(&signed_manifest(manifest))
            .map_err(|_| CryptoError::InvalidEncoding)?;
        vaults.push(PairingVault {
            manifest_revision: manifest.manifest_revision.clone(),
            signed_manifest_digest: URL_SAFE_NO_PAD.encode(Sha256::digest(signed_bytes)),
            vault_id: manifest.vault_id.clone(),
            vault_signing_key_fingerprint: manifest.vault_signing_key_fingerprint.clone(),
        });
        anchors.push(PinnedVaultTrust {
            vault_id,
            signing_public_key,
            signing_key_fingerprint,
            manifest_revision: parse_revision(&manifest.manifest_revision)?,
            manifest_signing_key_version: manifest.manifest_signing_key_version,
        });
    }
    let transcript = PairingTranscript {
        activation_id: activation_id.to_string(),
        agent_ed25519_fingerprint: URL_SAFE_NO_PAD.encode(identity.ed25519_fingerprint),
        agent_id: identity.agent_id.to_string(),
        agent_x25519_fingerprint: URL_SAFE_NO_PAD.encode(identity.x25519_fingerprint),
        algorithm_suite: ALGORITHM_SUITE,
        organization_id: identity.organization_id.to_string(),
        protocol_version: PROTOCOL_VERSION,
        vaults,
    };
    let canonical = serde_json::to_vec(&transcript).map_err(|_| CryptoError::InvalidEncoding)?;
    let mut input = Vec::with_capacity(PAIRING_DOMAIN.len() + 2 + canonical.len());
    input.extend_from_slice(PAIRING_DOMAIN);
    input.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    input.extend_from_slice(&canonical);
    let digest = Sha256::digest(input);
    let symbols: String = (0..12)
        .map(|index| {
            let bit = index * 5;
            let byte = bit / 8;
            let shift = 11usize.saturating_sub(bit % 8);
            let pair =
                u16::from_be_bytes([digest[byte], digest.get(byte + 1).copied().unwrap_or(0)]);
            CROCKFORD[((pair >> shift) & 31) as usize] as char
        })
        .collect();
    let sas = format!("{}-{}-{}", &symbols[..4], &symbols[4..8], &symbols[8..]);
    Ok(PairingCandidate {
        transcript,
        transcript_digest: URL_SAFE_NO_PAD.encode(digest),
        sas,
        anchors,
    })
}

pub fn confirm_pairing(
    candidate: PairingCandidate,
    member_confirmation: &MemberPairingConfirmation,
) -> Result<Vec<PinnedVaultTrust>, CryptoError> {
    if candidate.transcript_digest != member_confirmation.transcript_digest
        || candidate.sas != member_confirmation.short_authentication_string
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(candidate.anchors)
}

pub fn confirm_pairing_from_relay(
    candidate: PairingCandidate,
    relay: &PairingRelayStatus,
    now: OffsetDateTime,
) -> Result<Vec<PinnedVaultTrust>, CryptoError> {
    let expiry = OffsetDateTime::parse(&relay.expires_at, &Rfc3339)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if relay.activation_id != candidate.transcript.activation_id
        || relay.status != "confirmed"
        || now >= expiry
    {
        return Err(CryptoError::StaleInput);
    }
    let digest = relay
        .confirmed_pairing_digest
        .as_deref()
        .ok_or(CryptoError::AuthenticationFailed)?;
    if decode_base64url(digest)?.len() != 32 {
        return Err(CryptoError::InvalidLength);
    }
    let confirmation = MemberPairingConfirmation {
        transcript_digest: digest.to_owned(),
        short_authentication_string: candidate.sas.clone(),
    };
    confirm_pairing(candidate, &confirmation)
}

pub fn verify_manifest_update(
    manifest: &VaultManifestV2,
    identity: &AgentIdentityBinding,
    anchor: &PinnedVaultTrust,
) -> Result<PinnedVaultTrust, CryptoError> {
    validate_identity(manifest, identity)?;
    let vault_id = Uuid::parse_str(&manifest.vault_id).map_err(|_| CryptoError::InvalidEncoding)?;
    let revision = parse_revision(&manifest.manifest_revision)?;
    if vault_id != anchor.vault_id
        || revision <= anchor.manifest_revision
        || manifest.manifest_signing_key_version != anchor.manifest_signing_key_version
        || decode_32(&manifest.vault_signing_public_key)? != anchor.signing_public_key
        || decode_32(&manifest.vault_signing_key_fingerprint)? != anchor.signing_key_fingerprint
    {
        return Err(CryptoError::StaleInput);
    }
    let signature = decode_base64url(&manifest.signature)?;
    let canonical = serde_json::to_vec(&unsigned_manifest(manifest))
        .map_err(|_| CryptoError::InvalidEncoding)?;
    verify_domain_signature(
        SignatureProfile::VaultManifest,
        PROTOCOL_VERSION,
        &canonical,
        &anchor.signing_public_key,
        &signature,
    )?;
    Ok(PinnedVaultTrust {
        manifest_revision: revision,
        ..anchor.clone()
    })
}

#[derive(Debug, Default)]
pub struct TrustedVdkSet {
    current: Option<(u32, SecretBytes)>,
    pending: Option<(u32, SecretBytes)>,
}

impl TrustedVdkSet {
    pub fn install_pending(&mut self, version: u32, vdk: SecretBytes) -> Result<(), CryptoError> {
        let current = self.current.as_ref().map_or(0, |(version, _)| *version);
        if version <= current
            || self
                .pending
                .as_ref()
                .is_some_and(|(pending, _)| version <= *pending)
        {
            return Err(CryptoError::StaleInput);
        }
        self.pending = Some((version, vdk));
        Ok(())
    }

    pub fn promote_pending(&mut self, expected_version: u32) -> Result<(), CryptoError> {
        let pending = self.pending.take().ok_or(CryptoError::InvalidProfile)?;
        if pending.0 != expected_version {
            self.pending = Some(pending);
            return Err(CryptoError::StaleInput);
        }
        self.current = Some(pending);
        Ok(())
    }

    #[must_use]
    pub fn current(&self) -> Option<(u32, &SecretBytes)> {
        self.current.as_ref().map(|(version, key)| (*version, key))
    }

    pub fn purge(&mut self) {
        self.current = None;
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::TrustedVdkSet;
    use crate::{CryptoError, SecretBytes};

    #[test]
    fn vdk_rotation_is_monotonic_and_deactivation_purges_both_generations() {
        let mut keys = TrustedVdkSet::default();
        keys.install_pending(6, SecretBytes::new(vec![6; 32]))
            .unwrap();
        keys.promote_pending(6).unwrap();
        keys.install_pending(7, SecretBytes::new(vec![7; 32]))
            .unwrap();
        assert_eq!(keys.current().map(|(version, _)| version), Some(6));
        assert!(matches!(
            keys.install_pending(6, SecretBytes::new(vec![8; 32])),
            Err(CryptoError::StaleInput)
        ));
        keys.purge();
        assert!(keys.current().is_none());
        assert!(matches!(
            keys.promote_pending(7),
            Err(CryptoError::InvalidProfile)
        ));
    }
}
