use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use palladin_crypto::{Ed25519Identity, X25519Identity, verify_browser_pairing_state};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

const PREFIX: &str = "PALLADIN_AGENT_SETUP_V1:";
pub(crate) const MAX_PENDING_BROWSER_PAIRING_STATE_BYTES: usize = 8 * 1024;
const PENDING_BROWSER_PAIRING_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserPairingMetadata {
    pub display_name: Option<String>,
    pub agent_type: Option<String>,
}

/// Public, value-free restart state for exactly one local identity. The record is signed with
/// that identity's Ed25519 key before it is persisted. It deliberately contains neither the
/// organization credential nor an approval-session secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingBrowserPairingState {
    schema_version: u32,
    identity_id: String,
    host: String,
    pairing_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_type: Option<String>,
    encryption_public_key: String,
    signing_public_key: String,
    remove_profile_on_terminal: bool,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPendingBrowserPairingState<'a> {
    schema_version: u32,
    identity_id: &'a str,
    host: &'a str,
    pairing_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_type: Option<&'a str>,
    encryption_public_key: &'a str,
    signing_public_key: &'a str,
    remove_profile_on_terminal: bool,
}

impl PendingBrowserPairingState {
    pub(crate) fn create(
        identity_id: &str,
        host: &str,
        pairing_id: &str,
        metadata: &BrowserPairingMetadata,
        remove_profile_on_terminal: bool,
        encryption: &X25519Identity,
        signing: &Ed25519Identity,
    ) -> Result<Self, PendingBrowserPairingStateError> {
        let mut state = Self {
            schema_version: PENDING_BROWSER_PAIRING_SCHEMA_VERSION,
            identity_id: identity_id.to_owned(),
            host: host.to_owned(),
            pairing_id: pairing_id.to_owned(),
            display_name: metadata.display_name.clone(),
            agent_type: metadata.agent_type.clone(),
            encryption_public_key: STANDARD.encode(encryption.public_key()),
            signing_public_key: STANDARD.encode(signing.public_key()),
            remove_profile_on_terminal,
            signature: STANDARD.encode([0_u8; 64]),
        };
        state.validate_shape()?;
        let canonical = state.canonical_unsigned()?;
        state.signature = STANDARD.encode(signing.sign_browser_pairing_state(&canonical));
        Ok(state)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PendingBrowserPairingStateError> {
        let state: Self =
            serde_json::from_slice(bytes).map_err(|_| PendingBrowserPairingStateError::Invalid)?;
        state.validate_shape()?;
        Ok(state)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, PendingBrowserPairingStateError> {
        serde_json::to_vec(self).map_err(|_| PendingBrowserPairingStateError::Invalid)
    }

    pub(crate) fn verify(
        &self,
        expected_identity_id: &str,
        expected_host: &str,
        requested: &BrowserPairingMetadata,
        encryption: &X25519Identity,
        signing: &Ed25519Identity,
    ) -> Result<(), PendingBrowserPairingStateError> {
        self.validate_shape()?;
        if self.identity_id != expected_identity_id
            || self.host != expected_host
            || self.encryption_public_key != STANDARD.encode(encryption.public_key())
            || self.signing_public_key != STANDARD.encode(signing.public_key())
            || requested
                .display_name
                .as_ref()
                .is_some_and(|value| Some(value) != self.display_name.as_ref())
            || requested
                .agent_type
                .as_ref()
                .is_some_and(|value| Some(value) != self.agent_type.as_ref())
        {
            return Err(PendingBrowserPairingStateError::Conflict);
        }
        let signature = decode_fixed::<64>(&self.signature)?;
        verify_browser_pairing_state(
            signing.public_key(),
            &self.canonical_unsigned()?,
            &signature,
        )
        .map_err(|_| PendingBrowserPairingStateError::AuthenticationFailed)
    }

    pub(crate) fn pairing_id(&self) -> &str {
        &self.pairing_id
    }

    pub(crate) fn metadata(&self) -> BrowserPairingMetadata {
        BrowserPairingMetadata {
            display_name: self.display_name.clone(),
            agent_type: self.agent_type.clone(),
        }
    }

    pub(crate) fn remove_profile_on_terminal(&self) -> bool {
        self.remove_profile_on_terminal
    }

    fn validate_shape(&self) -> Result<(), PendingBrowserPairingStateError> {
        let normalized = BrowserPairingMetadata::resolve(
            None,
            self.display_name.as_deref(),
            self.agent_type.as_deref(),
        )
        .map_err(|_| PendingBrowserPairingStateError::Invalid)?;
        if self.schema_version != PENDING_BROWSER_PAIRING_SCHEMA_VERSION
            || !Uuid::parse_str(&self.pairing_id)
                .is_ok_and(|value| value.to_string() == self.pairing_id)
            || self.identity_id.is_empty()
            || self.host.is_empty()
            || normalized.display_name != self.display_name
            || normalized.agent_type != self.agent_type
            || STANDARD.encode(decode_fixed::<32>(&self.encryption_public_key)?)
                != self.encryption_public_key
            || STANDARD.encode(decode_fixed::<32>(&self.signing_public_key)?)
                != self.signing_public_key
            || STANDARD.encode(decode_fixed::<64>(&self.signature)?) != self.signature
        {
            return Err(PendingBrowserPairingStateError::Invalid);
        }
        Ok(())
    }

    fn canonical_unsigned(&self) -> Result<Vec<u8>, PendingBrowserPairingStateError> {
        serde_json::to_vec(&UnsignedPendingBrowserPairingState {
            schema_version: self.schema_version,
            identity_id: &self.identity_id,
            host: &self.host,
            pairing_id: &self.pairing_id,
            display_name: self.display_name.as_deref(),
            agent_type: self.agent_type.as_deref(),
            encryption_public_key: &self.encryption_public_key,
            signing_public_key: &self.signing_public_key,
            remove_profile_on_terminal: self.remove_profile_on_terminal,
        })
        .map_err(|_| PendingBrowserPairingStateError::Invalid)
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], PendingBrowserPairingStateError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| PendingBrowserPairingStateError::Invalid)?;
    bytes
        .try_into()
        .map_err(|_| PendingBrowserPairingStateError::Invalid)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum PendingBrowserPairingStateError {
    #[error("pending browser pairing state is invalid")]
    Invalid,
    #[error("pending browser pairing state does not match this invocation")]
    Conflict,
    #[error("pending browser pairing state authentication failed")]
    AuthenticationFailed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SetupDescriptor {
    v: u8,
    #[serde(
        rename = "userPreferredDisplayName",
        skip_serializing_if = "Option::is_none"
    )]
    user_preferred_display_name: Option<String>,
}

impl BrowserPairingMetadata {
    pub fn resolve(
        descriptor: Option<&str>,
        display_name: Option<&str>,
        agent_type: Option<&str>,
    ) -> Result<Self, SetupDescriptorError> {
        let descriptor_name = descriptor.map(parse_descriptor).transpose()?.flatten();
        let supplied_name = normalize_metadata(display_name, 64)?;
        if descriptor_name.is_some() && supplied_name.is_some() && descriptor_name != supplied_name
        {
            return Err(SetupDescriptorError::ConflictingDisplayName);
        }
        Ok(Self {
            display_name: descriptor_name.or(supplied_name),
            agent_type: normalize_metadata(agent_type, 100)?,
        })
    }
}

pub fn encode_setup_descriptor(display_name: Option<&str>) -> Result<String, SetupDescriptorError> {
    let descriptor = SetupDescriptor {
        v: 1,
        user_preferred_display_name: normalize_metadata(display_name, 64)?,
    };
    let json = serde_json::to_vec(&descriptor).map_err(|_| SetupDescriptorError::Invalid)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

fn parse_descriptor(value: &str) -> Result<Option<String>, SetupDescriptorError> {
    let encoded = value
        .strip_prefix(PREFIX)
        .ok_or(SetupDescriptorError::Invalid)?;
    let json = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SetupDescriptorError::Invalid)?;
    let descriptor: SetupDescriptor =
        serde_json::from_slice(&json).map_err(|_| SetupDescriptorError::Invalid)?;
    if descriptor.v != 1 {
        return Err(SetupDescriptorError::Invalid);
    }
    let canonical = serde_json::to_vec(&descriptor).map_err(|_| SetupDescriptorError::Invalid)?;
    if canonical != json {
        return Err(SetupDescriptorError::Invalid);
    }
    normalize_metadata(descriptor.user_preferred_display_name.as_deref(), 64)
}

fn normalize_metadata(
    value: Option<&str>,
    max_chars: usize,
) -> Result<Option<String>, SetupDescriptorError> {
    let Some(value) = value else { return Ok(None) };
    let normalized = value.trim().nfc().collect::<String>();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.chars().count() > max_chars || normalized.chars().any(forbidden_character) {
        return Err(SetupDescriptorError::InvalidMetadata);
    }
    Ok(Some(normalized))
}

fn forbidden_character(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{2028}' | '\u{2029}')
        || matches!(
            character as u32,
            0x00ad
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x2064
                | 0x2066..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
                | 0x0600..=0x0605
                | 0x0890..=0x0891
        )
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SetupDescriptorError {
    #[error("the Palladin setup descriptor is invalid or non-canonical")]
    Invalid,
    #[error("Agent display name or type contains unsupported characters or is too long")]
    InvalidMetadata,
    #[error("the descriptor and separate display name disagree")]
    ConflictingDisplayName,
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use palladin_crypto::{Ed25519Identity, X25519Identity};

    use super::{
        BrowserPairingMetadata, PREFIX, PendingBrowserPairingState, encode_setup_descriptor,
    };

    #[test]
    fn descriptor_round_trip_and_separate_type_preserve_custom_string() {
        let descriptor = encode_setup_descriptor(Some("  Spokojna Wydra  ")).expect("descriptor");
        let metadata = BrowserPairingMetadata::resolve(
            Some(&descriptor),
            Some("Spokojna Wydra"),
            Some("custom/runtime"),
        )
        .expect("metadata");
        assert_eq!(metadata.display_name.as_deref(), Some("Spokojna Wydra"));
        assert_eq!(metadata.agent_type.as_deref(), Some("custom/runtime"));
    }

    #[test]
    fn rejects_prompt_control_characters_and_conflicting_name() {
        let descriptor = encode_setup_descriptor(Some("Bursztynowy Lis")).expect("descriptor");
        assert!(BrowserPairingMetadata::resolve(Some(&descriptor), Some("Inna"), None).is_err());
        assert!(BrowserPairingMetadata::resolve(None, Some("safe\u{202e}unsafe"), None).is_err());
    }

    #[test]
    fn blank_values_are_absent() {
        let metadata =
            BrowserPairingMetadata::resolve(None, Some("  "), Some("\t")).expect("blank values");
        assert_eq!(metadata.display_name, None);
        assert_eq!(metadata.agent_type, None);
    }

    #[test]
    fn metadata_uses_code_point_limits_and_normalizes_before_comparison() {
        let decomposed = "Cafe\u{301}";
        let descriptor = encode_setup_descriptor(Some(decomposed)).expect("descriptor");
        let metadata = BrowserPairingMetadata::resolve(
            Some(&descriptor),
            Some("Café"),
            Some(&"🦀".repeat(100)),
        )
        .expect("NFC-equivalent input");
        assert_eq!(metadata.display_name.as_deref(), Some("Café"));
        assert_eq!(metadata.agent_type.expect("type").chars().count(), 100);
        assert!(BrowserPairingMetadata::resolve(None, None, Some(&"🦀".repeat(101))).is_err());
    }

    #[test]
    fn descriptor_rejects_noncanonical_json_versions_and_extra_fields() {
        for json in [
            r#"{"v":2}"#,
            r#"{ "v":1}"#,
            r#"{"userPreferredDisplayName":"Fox","v":1}"#,
            r#"{"v":1,"unexpected":true}"#,
        ] {
            let descriptor = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
            assert!(BrowserPairingMetadata::resolve(Some(&descriptor), None, None).is_err());
        }
    }

    #[test]
    fn pending_state_is_identity_bound_and_detects_tampering_or_resume_conflicts() {
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("encryption");
        let signing = Ed25519Identity::from_seed(vec![9; 32]).expect("signing");
        let requested =
            BrowserPairingMetadata::resolve(None, Some("Spokojna Wydra"), Some("custom/runtime"))
                .expect("metadata");
        let state = PendingBrowserPairingState::create(
            "identity-id",
            "https://api.palladin.io",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            &requested,
            true,
            &encryption,
            &signing,
        )
        .expect("pending state");
        let encoded = state.encode().expect("encode");
        let decoded = PendingBrowserPairingState::decode(&encoded).expect("decode");
        decoded
            .verify(
                "identity-id",
                "https://api.palladin.io",
                &BrowserPairingMetadata::resolve(None, None, None).expect("empty metadata"),
                &encryption,
                &signing,
            )
            .expect("verified resume");

        let conflicting =
            BrowserPairingMetadata::resolve(None, Some("Inna"), None).expect("conflict");
        assert!(
            decoded
                .verify(
                    "identity-id",
                    "https://api.palladin.io",
                    &conflicting,
                    &encryption,
                    &signing,
                )
                .is_err()
        );

        let mut tampered = decoded;
        tampered.display_name = Some("Bursztynowy Lis".to_owned());
        assert!(
            tampered
                .verify(
                    "identity-id",
                    "https://api.palladin.io",
                    &BrowserPairingMetadata::resolve(None, None, None).expect("empty metadata"),
                    &encryption,
                    &signing,
                )
                .is_err()
        );
    }
}
