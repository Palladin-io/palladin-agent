use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    AgentEncryptionKeys, CryptoError, RecipientPublicKey, SecretBytes,
    key_wrapper::{MAX_SELF_SEAL_OVERHEAD_BYTES, SELF_SEAL_OVERHEAD_BYTES, seal_to_self},
};

const CACHE_MAGIC: &[u8; 8] = b"PLDNCCH1";
const CACHE_BINDING_DOMAIN: &[u8] = b"palladin.local-discovery-cache.v1\0";
const BINDING_DIGEST_BYTES: usize = 32;
const MAX_BINDING_BYTES: usize = 4 * 1024;
const MAX_CACHE_PLAINTEXT_BYTES: usize = 68 * 1024 * 1024;
const HEADER_BYTES: usize = CACHE_MAGIC.len() + BINDING_DIGEST_BYTES;

/// Seals the cache to the Agent's own current public key so a write needs no private key.
pub fn seal_local_discovery_cache(
    recipient: &RecipientPublicKey,
    binding: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_lengths(binding, plaintext.len())?;
    let mut bound = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + plaintext.len()));
    bound.extend_from_slice(CACHE_MAGIC);
    bound.extend_from_slice(&binding_digest(binding));
    bound.extend_from_slice(plaintext);
    seal_to_self(recipient, bound.as_ref())
}

/// Opens a cache sealed to any held key, so a cache written before a key rotation stays
/// readable until it is rewritten for the current key.
pub fn open_local_discovery_cache(
    keys: &AgentEncryptionKeys,
    binding: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    if binding.is_empty()
        || binding.len() > MAX_BINDING_BYTES
        || ciphertext.len() < HEADER_BYTES + SELF_SEAL_OVERHEAD_BYTES
        || ciphertext.len()
            > MAX_CACHE_PLAINTEXT_BYTES + HEADER_BYTES + MAX_SELF_SEAL_OVERHEAD_BYTES
    {
        return Err(CryptoError::InvalidLength);
    }
    let opened = keys
        .iter()
        .find_map(|key| key.open_sealed_to_self(ciphertext).ok())
        .ok_or(CryptoError::AuthenticationFailed)?;
    if opened.len() < HEADER_BYTES
        || opened[..CACHE_MAGIC.len()].ct_eq(CACHE_MAGIC).unwrap_u8() != 1
        || opened[CACHE_MAGIC.len()..HEADER_BYTES]
            .ct_eq(&binding_digest(binding))
            .unwrap_u8()
            != 1
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(SecretBytes::new(opened[HEADER_BYTES..].to_vec()))
}

fn validate_lengths(binding: &[u8], plaintext_len: usize) -> Result<(), CryptoError> {
    if binding.is_empty()
        || binding.len() > MAX_BINDING_BYTES
        || plaintext_len == 0
        || plaintext_len > MAX_CACHE_PLAINTEXT_BYTES
    {
        return Err(CryptoError::InvalidLength);
    }
    Ok(())
}

fn binding_digest(binding: &[u8]) -> [u8; BINDING_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(CACHE_BINDING_DOMAIN);
    digest.update((binding.len() as u64).to_be_bytes());
    digest.update(binding);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use crate::{
        AgentEncryptionKeys, EncryptionIdentity, open_local_discovery_cache,
        seal_local_discovery_cache,
    };

    fn keys(
        current: EncryptionIdentity,
        previous: Option<EncryptionIdentity>,
    ) -> AgentEncryptionKeys {
        AgentEncryptionKeys::new(current, previous).expect("keys")
    }

    #[test]
    fn local_discovery_cache_is_sealed_to_the_agent_identity_and_binding() {
        let identity = keys(EncryptionIdentity::generate().expect("identity"), None);
        let other = keys(
            EncryptionIdentity::generate().expect("other identity"),
            None,
        );
        let binding = b"profile-a\0agent-a\0generation-1";
        let plaintext = b"agent-visible discovery cache";

        let sealed = seal_local_discovery_cache(
            &identity.current().recipient_public_key(),
            binding,
            plaintext,
        )
        .expect("seal cache");
        let opened = open_local_discovery_cache(&identity, binding, &sealed).expect("open cache");

        assert_eq!(opened.expose_for_crypto_operation(), plaintext);
        assert!(open_local_discovery_cache(&other, binding, &sealed).is_err());
        assert!(
            open_local_discovery_cache(&identity, b"profile-a\0agent-a\0generation-2", &sealed)
                .is_err()
        );
    }

    #[test]
    fn a_cache_sealed_before_rotation_opens_with_the_previous_key() {
        let previous = EncryptionIdentity::from_legacy_storage(vec![7; 32]).expect("previous");
        let sealed =
            seal_local_discovery_cache(&previous.recipient_public_key(), b"binding", b"cache")
                .expect("seal cache");
        let rotated = keys(
            EncryptionIdentity::generate().expect("current"),
            Some(previous),
        );
        let opened = open_local_discovery_cache(&rotated, b"binding", &sealed).expect("open");
        assert_eq!(opened.expose_for_crypto_operation(), b"cache");
    }

    #[test]
    fn local_discovery_cache_rejects_ciphertext_tampering() {
        let identity = keys(EncryptionIdentity::generate().expect("identity"), None);
        let mut sealed = seal_local_discovery_cache(
            &identity.current().recipient_public_key(),
            b"binding",
            b"cache",
        )
        .expect("seal cache");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;

        assert!(open_local_discovery_cache(&identity, b"binding", &sealed).is_err());
    }
}
