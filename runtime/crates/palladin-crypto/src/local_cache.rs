use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{CryptoError, SecretBytes, X25519Identity};

const CACHE_MAGIC: &[u8; 8] = b"PLDNCCH1";
const CACHE_BINDING_DOMAIN: &[u8] = b"palladin.local-discovery-cache.v1\0";
const BINDING_DIGEST_BYTES: usize = 32;
const SEALED_BOX_OVERHEAD: usize = 48;
const MAX_BINDING_BYTES: usize = 4 * 1024;
const MAX_CACHE_PLAINTEXT_BYTES: usize = 68 * 1024 * 1024;
const HEADER_BYTES: usize = CACHE_MAGIC.len() + BINDING_DIGEST_BYTES;

pub fn seal_local_discovery_cache(
    recipient_public_key: &[u8; 32],
    binding: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_lengths(binding, plaintext.len())?;
    let mut bound = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + plaintext.len()));
    bound.extend_from_slice(CACHE_MAGIC);
    bound.extend_from_slice(&binding_digest(binding));
    bound.extend_from_slice(plaintext);
    crypto_box::PublicKey::from(*recipient_public_key)
        .seal(&mut OsRng, bound.as_ref())
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn open_local_discovery_cache(
    recipient: &X25519Identity,
    binding: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    if binding.is_empty()
        || binding.len() > MAX_BINDING_BYTES
        || ciphertext.len() < HEADER_BYTES + SEALED_BOX_OVERHEAD
        || ciphertext.len() > MAX_CACHE_PLAINTEXT_BYTES + HEADER_BYTES + SEALED_BOX_OVERHEAD
    {
        return Err(CryptoError::InvalidLength);
    }
    let secret = crypto_box::SecretKey::from_bytes(recipient.static_secret().to_bytes());
    let opened = Zeroizing::new(
        secret
            .unseal(ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
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
    use crate::{X25519Identity, open_local_discovery_cache, seal_local_discovery_cache};

    #[test]
    fn local_discovery_cache_is_sealed_to_the_agent_identity_and_binding() {
        let identity = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let other = X25519Identity::from_private_bytes(vec![9; 32]).expect("other identity");
        let binding = b"profile-a\0agent-a\0generation-1";
        let plaintext = b"agent-visible discovery cache";

        let sealed = seal_local_discovery_cache(identity.public_key(), binding, plaintext)
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
    fn local_discovery_cache_rejects_ciphertext_tampering() {
        let identity = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let mut sealed = seal_local_discovery_cache(identity.public_key(), b"binding", b"cache")
            .expect("seal cache");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;

        assert!(open_local_discovery_cache(&identity, b"binding", &sealed).is_err());
    }
}
