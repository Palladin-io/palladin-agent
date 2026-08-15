use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretBox};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CryptoError, Ed25519Identity, EncodedSuitePayload, EnvelopeBinding, EnvelopeDescriptor,
    EnvelopePurpose, EnvelopeScope, PROTOCOL_VERSION, RecipientKeyKind, SealedWrappedKey,
    VAULT_XCHACHA_V1, WrapperContext, WrapperPurpose, X25519_WRAPPER_V1, X25519SealedBoxSuite,
    XChaChaVaultSuite, compute_key_fingerprint,
};

const ENCRYPTED_REASON_SIGNATURE_PREFIX: &[u8] = b"PLDNV2SIG:ENCRYPTED-REASON:";
const MAXIMUM_REASON_PAYLOAD_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedReasonEnvelope {
    pub descriptor: EncryptedReasonDescriptor,
    pub encoded_suite_payload: String,
    pub wrapped_reason_dek: WrappedReasonDek,
    pub agent_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedReasonDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    pub purpose: String,
    pub scope: EncryptedReasonScope,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: EncryptedReasonBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedReasonScope {
    pub organization_id: String,
    pub vault_id: String,
    pub entry_id: String,
    pub grant_or_request_id: String,
    pub agent_id: String,
    pub member_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedReasonBinding {
    pub wrapper_suite_id: String,
    pub recipient_key_version: u32,
    pub recipient_key_fingerprint: String,
    pub requested_methods: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedReasonDek {
    pub descriptor: ReasonWrapperDescriptor,
    pub encoded_sealed_key_package: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasonWrapperDescriptor {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    pub purpose: String,
    pub scope: EncryptedReasonScope,
    pub resource_revision: String,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    pub recipient_key_kind: String,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: String,
    pub parent_descriptor_hash: String,
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptedReasonContext {
    pub organization_id: Uuid,
    pub vault_id: Uuid,
    pub entry_id: Uuid,
    pub grant_request_id: Uuid,
    pub agent_id: Uuid,
    pub request_revision: u64,
    pub reason_key_version: u32,
    pub agent_message_key_version: u32,
    pub member_key_generation: u32,
    pub requested_methods: u16,
    pub recipient_agent_message_public_key: [u8; 32],
    pub recipient_agent_message_key_fingerprint: [u8; 32],
}

#[derive(Serialize)]
struct ReasonPlaintext<'a> {
    reason: &'a str,
}

pub fn encrypt_reason(
    reason: &str,
    context: EncryptedReasonContext,
    signer: &Ed25519Identity,
) -> Result<EncryptedReasonEnvelope, CryptoError> {
    let reason = reason.trim();
    if reason.is_empty()
        || context.request_revision == 0
        || context.reason_key_version == 0
        || context.agent_message_key_version == 0
        || context.member_key_generation == 0
        || context.requested_methods == 0
        || context.recipient_agent_message_public_key == [0; 32]
    {
        return Err(CryptoError::InvalidProfile);
    }
    let expected_fingerprint = compute_key_fingerprint(
        &context.recipient_agent_message_public_key,
        RecipientKeyKind::VaultMessageX25519,
    );
    if expected_fingerprint != context.recipient_agent_message_key_fingerprint {
        return Err(CryptoError::AuthenticationFailed);
    }

    let scope = EnvelopeScope {
        organization_id: *context.organization_id.as_bytes(),
        vault_id: *context.vault_id.as_bytes(),
        entry_id: Some(*context.entry_id.as_bytes()),
        grant_or_request_id: Some(*context.grant_request_id.as_bytes()),
        agent_id: Some(*context.agent_id.as_bytes()),
        member_id: None,
    };
    let descriptor = EnvelopeDescriptor {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
        purpose: EnvelopePurpose::EncryptedReason,
        scope: scope.clone(),
        resource_revision: context.request_revision,
        key_version: context.reason_key_version,
        member_key_generation: Some(context.member_key_generation),
        binding: EnvelopeBinding::Reason {
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            agent_message_key_version: context.agent_message_key_version,
            recipient_vault_message_key_fingerprint: context
                .recipient_agent_message_key_fingerprint,
            requested_methods: context.requested_methods,
        },
    };
    let descriptor_bytes = descriptor.canonical_aad()?;
    let parent_descriptor_hash: [u8; 32] = Sha256::digest(&descriptor_bytes).into();
    let wrapper_context = WrapperContext {
        protocol_version: PROTOCOL_VERSION,
        wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
        purpose: WrapperPurpose::ReasonDek,
        scope,
        resource_revision: context.request_revision,
        wrapped_key_version: context.reason_key_version,
        member_key_generation: Some(context.member_key_generation),
        recipient_key_kind: RecipientKeyKind::VaultMessageX25519,
        recipient_key_version: context.agent_message_key_version,
        recipient_fingerprint: context.recipient_agent_message_key_fingerprint,
        parent_descriptor_hash: Some(parent_descriptor_hash),
    };

    let mut dek_bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(dek_bytes.as_mut()).map_err(|_| CryptoError::RandomGenerationFailed)?;
    let dek = SecretBox::new(Box::new(*dek_bytes));
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&ReasonPlaintext { reason })
            .map_err(|_| CryptoError::InvalidEncoding)?,
    );
    if plaintext.len().saturating_add(16) > MAXIMUM_REASON_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let payload_key = XChaChaVaultSuite::derive_key(dek.expose_secret(), &descriptor)?;
    let payload = XChaChaVaultSuite::seal(&payload_key, &plaintext, &descriptor_bytes)?;
    let wrapped = X25519SealedBoxSuite::wrap(
        &dek,
        context.recipient_agent_message_public_key,
        &wrapper_context,
    )?;
    let transcript = signature_transcript(&descriptor_bytes, &payload, &wrapped)?;

    let serialized_scope = EncryptedReasonScope {
        organization_id: context.organization_id.to_string(),
        vault_id: context.vault_id.to_string(),
        entry_id: context.entry_id.to_string(),
        grant_or_request_id: context.grant_request_id.to_string(),
        agent_id: context.agent_id.to_string(),
        member_id: None,
    };
    let recipient_fingerprint =
        URL_SAFE_NO_PAD.encode(context.recipient_agent_message_key_fingerprint);
    let revision = context.request_revision.to_string();
    Ok(EncryptedReasonEnvelope {
        descriptor: EncryptedReasonDescriptor {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
            purpose: "encryptedReason".to_owned(),
            scope: serialized_scope.clone(),
            resource_revision: revision.clone(),
            key_version: context.reason_key_version,
            member_key_generation: Some(context.member_key_generation),
            binding: EncryptedReasonBinding {
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                recipient_key_version: context.agent_message_key_version,
                recipient_key_fingerprint: recipient_fingerprint.clone(),
                requested_methods: context.requested_methods,
            },
        },
        encoded_suite_payload: URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        wrapped_reason_dek: WrappedReasonDek {
            descriptor: ReasonWrapperDescriptor {
                protocol_version: PROTOCOL_VERSION,
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                purpose: "reasonDek".to_owned(),
                scope: serialized_scope,
                resource_revision: revision,
                wrapped_key_version: context.reason_key_version,
                member_key_generation: Some(context.member_key_generation),
                recipient_key_kind: "vaultMessageX25519".to_owned(),
                recipient_key_version: context.agent_message_key_version,
                recipient_fingerprint,
                parent_descriptor_hash: URL_SAFE_NO_PAD.encode(parent_descriptor_hash),
            },
            encoded_sealed_key_package: URL_SAFE_NO_PAD.encode(wrapped.as_bytes()),
        },
        agent_signature: URL_SAFE_NO_PAD.encode(signer.sign(&transcript)),
    })
}

fn signature_transcript(
    descriptor: &[u8],
    payload: &EncodedSuitePayload,
    wrapper: &SealedWrappedKey,
) -> Result<Vec<u8>, CryptoError> {
    let suite = X25519_WRAPPER_V1.as_bytes();
    let suite_length = u16::try_from(suite.len()).map_err(|_| CryptoError::InvalidLength)?;
    let mut transcript = Vec::with_capacity(
        ENCRYPTED_REASON_SIGNATURE_PREFIX.len()
            + 2
            + descriptor.len()
            + payload.as_bytes().len()
            + 2
            + suite.len()
            + wrapper.as_bytes().len(),
    );
    transcript.extend_from_slice(ENCRYPTED_REASON_SIGNATURE_PREFIX);
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(descriptor);
    transcript.extend_from_slice(payload.as_bytes());
    transcript.extend_from_slice(&suite_length.to_be_bytes());
    transcript.extend_from_slice(suite);
    transcript.extend_from_slice(wrapper.as_bytes());
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    use super::*;
    use crate::{X25519Identity, compute_key_fingerprint};

    fn context(recipient: &X25519Identity) -> EncryptedReasonContext {
        EncryptedReasonContext {
            organization_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            vault_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            entry_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            grant_request_id: Uuid::parse_str("77777777-7777-4777-8777-777777777777").unwrap(),
            agent_id: Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap(),
            request_revision: 1,
            reason_key_version: 1,
            agent_message_key_version: 4,
            member_key_generation: 4,
            requested_methods: 1,
            recipient_agent_message_public_key: *recipient.public_key(),
            recipient_agent_message_key_fingerprint: compute_key_fingerprint(
                recipient.public_key(),
                RecipientKeyKind::VaultMessageX25519,
            ),
        }
    }

    #[test]
    fn current_reason_contract_round_trips_and_verifies() {
        let recipient = X25519Identity::from_private_bytes(vec![7; 32]).unwrap();
        let signer = Ed25519Identity::from_seed(vec![9; 32]).unwrap();
        let context = context(&recipient);
        let canary = "Need access to the synthetic credential";
        let envelope = encrypt_reason(canary, context, &signer).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains(canary));
        assert!(json.contains("\"purpose\":\"encryptedReason\""));
        assert!(json.contains("\"recipientKeyKind\":\"vaultMessageX25519\""));

        let descriptor = EnvelopeDescriptor {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
            purpose: EnvelopePurpose::EncryptedReason,
            scope: EnvelopeScope {
                organization_id: *context.organization_id.as_bytes(),
                vault_id: *context.vault_id.as_bytes(),
                entry_id: Some(*context.entry_id.as_bytes()),
                grant_or_request_id: Some(*context.grant_request_id.as_bytes()),
                agent_id: Some(*context.agent_id.as_bytes()),
                member_id: None,
            },
            resource_revision: 1,
            key_version: 1,
            member_key_generation: Some(4),
            binding: EnvelopeBinding::Reason {
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                agent_message_key_version: 4,
                recipient_vault_message_key_fingerprint: context
                    .recipient_agent_message_key_fingerprint,
                requested_methods: 1,
            },
        };
        let descriptor_bytes = descriptor.canonical_aad().unwrap();
        let parent_hash: [u8; 32] = Sha256::digest(&descriptor_bytes).into();
        let wrapper_context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::ReasonDek,
            scope: descriptor.scope.clone(),
            resource_revision: 1,
            wrapped_key_version: 1,
            member_key_generation: Some(4),
            recipient_key_kind: RecipientKeyKind::VaultMessageX25519,
            recipient_key_version: 4,
            recipient_fingerprint: context.recipient_agent_message_key_fingerprint,
            parent_descriptor_hash: Some(parent_hash),
        };
        let wrapped = SealedWrappedKey::from_bytes(
            URL_SAFE_NO_PAD
                .decode(&envelope.wrapped_reason_dek.encoded_sealed_key_package)
                .unwrap(),
        )
        .unwrap();
        let dek = X25519SealedBoxSuite::unwrap(&wrapped, &recipient, &wrapper_context).unwrap();
        let payload = EncodedSuitePayload::from_bytes(
            URL_SAFE_NO_PAD
                .decode(&envelope.encoded_suite_payload)
                .unwrap(),
        )
        .unwrap();
        let payload_key = XChaChaVaultSuite::derive_key(dek.expose_secret(), &descriptor).unwrap();
        let plaintext = XChaChaVaultSuite::open(&payload_key, &payload, &descriptor_bytes).unwrap();
        let expected = Zeroizing::new(format!(r#"{{"reason":"{canary}"}}"#).into_bytes());
        let expected_bytes: &[u8] = expected.as_ref();
        let plaintext_matches = plaintext.expose_secret() == expected_bytes;
        assert!(plaintext_matches, "decrypted reason fixture diverged");

        let transcript = signature_transcript(&descriptor_bytes, &payload, &wrapped).unwrap();
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(envelope.agent_signature).unwrap())
                .unwrap();
        VerifyingKey::from_bytes(signer.public_key())
            .unwrap()
            .verify(&transcript, &signature)
            .unwrap();
    }

    #[test]
    fn current_reason_contract_rejects_wrong_recipient_and_oversize_reason() {
        let recipient = X25519Identity::from_private_bytes(vec![7; 32]).unwrap();
        let signer = Ed25519Identity::from_seed(vec![9; 32]).unwrap();
        let mut invalid = context(&recipient);
        invalid.recipient_agent_message_key_fingerprint = [1; 32];
        assert_eq!(
            encrypt_reason("reason", invalid, &signer),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            encrypt_reason(&"x".repeat(4_096), context(&recipient), &signer),
            Err(CryptoError::InvalidLength)
        );
    }
}
