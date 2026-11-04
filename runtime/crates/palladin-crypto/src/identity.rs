use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secrecy::{ExposeSecret, SecretSlice};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, EncryptionIdentity, RecipientKeyKind, RecipientPublicKey,
    key_wrapper::PROTOCOL_VERSION,
};

const PROFILE_BINDING_DOMAIN: &[u8] = b"palladin.profile-trust.v1\0";
const BROWSER_PAIRING_STATE_DOMAIN: &[u8] = b"palladin.browser-pairing-state.v1\0";
const ENCRYPTION_KEY_ROTATION_DOMAIN: &[u8] = b"palladin.agent-encryption-key-rotation.v1\0";

pub struct X25519Identity {
    private_key: SecretSlice<u8>,
    public_key: [u8; 32],
}

impl X25519Identity {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut private_key = vec![0u8; 32];
        getrandom::fill(&mut private_key).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Self::from_private_bytes(private_key)
    }

    pub fn from_private_bytes(mut private_key: Vec<u8>) -> Result<Self, CryptoError> {
        if private_key.len() != 32 {
            private_key.zeroize();
            return Err(CryptoError::InvalidLength);
        }

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(&private_key);
        let static_secret = Zeroizing::new(StaticSecret::from(*key_bytes));
        let public_key = PublicKey::from(&*static_secret).to_bytes();

        Ok(Self {
            private_key: private_key.into(),
            public_key,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub(crate) fn static_secret(&self) -> Zeroizing<StaticSecret> {
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(self.private_key.expose_secret());
        Zeroizing::new(StaticSecret::from(*key_bytes))
    }

    #[must_use]
    pub fn private_key_for_secure_storage(&self) -> &[u8] {
        self.private_key.expose_secret()
    }
}

impl std::fmt::Debug for X25519Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X25519Identity")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &"[PUBLIC KEY]")
            .finish()
    }
}

pub struct Ed25519Identity {
    seed: SecretSlice<u8>,
    public_key: [u8; 32],
}

impl Ed25519Identity {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = vec![0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Self::from_seed(seed)
    }

    pub fn from_seed(mut seed: Vec<u8>) -> Result<Self, CryptoError> {
        if seed.len() != 32 {
            seed.zeroize();
            return Err(CryptoError::InvalidLength);
        }

        let signing_key = signing_key_from_slice(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            seed: seed.into(),
            public_key,
        })
    }

    pub fn from_libsodium_secret(secret: Vec<u8>) -> Result<Self, CryptoError> {
        let secret = Zeroizing::new(secret);
        if secret.len() != 64 {
            return Err(CryptoError::InvalidLength);
        }

        let identity = Self::from_seed(secret[..32].to_vec())?;
        if secret[32..] != identity.public_key {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(identity)
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn libsodium_secret_for_secure_storage(&self) -> SecretSlice<u8> {
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(self.seed.expose_secret());
        secret.extend_from_slice(&self.public_key);
        secret.into()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = signing_key_from_slice(self.seed.expose_secret());
        signing_key.sign(message).to_bytes()
    }

    /// Sign a canonical, public profile trust tuple without exposing a generic
    /// signing oracle to callers.
    #[must_use]
    pub fn sign_profile_binding(&self, canonical_binding: &[u8]) -> [u8; 64] {
        let mut message =
            Vec::with_capacity(PROFILE_BINDING_DOMAIN.len() + canonical_binding.len());
        message.extend_from_slice(PROFILE_BINDING_DOMAIN);
        message.extend_from_slice(canonical_binding);
        self.sign(&message)
    }

    /// Sign the value-free, crash-recovery state for one browser pairing. Keeping this
    /// domain separate from profile trust prevents a valid pairing record from being
    /// replayed as another signed runtime artifact.
    #[must_use]
    pub fn sign_browser_pairing_state(&self, canonical_state: &[u8]) -> [u8; 64] {
        let mut message =
            Vec::with_capacity(BROWSER_PAIRING_STATE_DOMAIN.len() + canonical_state.len());
        message.extend_from_slice(BROWSER_PAIRING_STATE_DOMAIN);
        message.extend_from_slice(canonical_state);
        self.sign(&message)
    }
}

/// The statement an Agent signs to replace its encryption key without re-pairing:
///
/// `ASCII("palladin.agent-encryption-key-rotation.v1") || 0x00 || u16be(2) || agentId[16] ||
/// previousFingerprint[32] || u16be(len) || ASCII(nextSuiteId) || nextFingerprint[32]`
///
/// Both fingerprints are suite fingerprints with key kind `agent-encryption`, so the statement
/// commits to both full public keys and suites. The previous fingerprint ties it to one
/// transition and prevents replay after a later rotation.
#[must_use]
pub fn encryption_key_rotation_statement(
    agent_id: &[u8; 16],
    previous: &RecipientPublicKey,
    next: &RecipientPublicKey,
) -> Vec<u8> {
    let suite = next.suite_id().as_bytes();
    let mut statement = Vec::with_capacity(ENCRYPTION_KEY_ROTATION_DOMAIN.len() + 84 + suite.len());
    statement.extend_from_slice(ENCRYPTION_KEY_ROTATION_DOMAIN);
    statement.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    statement.extend_from_slice(agent_id);
    statement.extend_from_slice(&previous.fingerprint(RecipientKeyKind::AgentEncryption));
    statement.extend_from_slice(&(suite.len() as u16).to_be_bytes());
    statement.extend_from_slice(suite);
    statement.extend_from_slice(&next.fingerprint(RecipientKeyKind::AgentEncryption));
    statement
}

impl Ed25519Identity {
    #[must_use]
    pub fn sign_encryption_key_rotation(
        &self,
        agent_id: &[u8; 16],
        previous: &EncryptionIdentity,
        next: &EncryptionIdentity,
    ) -> [u8; 64] {
        self.sign(&encryption_key_rotation_statement(
            agent_id,
            &previous.recipient_public_key(),
            &next.recipient_public_key(),
        ))
    }
}

pub fn verify_encryption_key_rotation(
    signing_public_key: &[u8; 32],
    agent_id: &[u8; 16],
    previous: &RecipientPublicKey,
    next: &RecipientPublicKey,
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(signing_public_key)
        .map_err(|_| CryptoError::InvalidEncoding)?
        .verify(
            &encryption_key_rotation_statement(agent_id, previous, next),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn verify_profile_binding(
    public_key: &[u8; 32],
    canonical_binding: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidEncoding)?;
    let mut message = Vec::with_capacity(PROFILE_BINDING_DOMAIN.len() + canonical_binding.len());
    message.extend_from_slice(PROFILE_BINDING_DOMAIN);
    message.extend_from_slice(canonical_binding);
    verifying_key
        .verify(&message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn verify_browser_pairing_state(
    public_key: &[u8; 32],
    canonical_state: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidEncoding)?;
    let mut message =
        Vec::with_capacity(BROWSER_PAIRING_STATE_DOMAIN.len() + canonical_state.len());
    message.extend_from_slice(BROWSER_PAIRING_STATE_DOMAIN);
    message.extend_from_slice(canonical_state);
    verifying_key
        .verify(&message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn signing_key_from_slice(seed: &[u8]) -> SigningKey {
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    seed_bytes.copy_from_slice(seed);
    SigningKey::from_bytes(&seed_bytes)
}

impl std::fmt::Debug for Ed25519Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ed25519Identity")
            .field("seed", &"[REDACTED]")
            .field("public_key", &"[PUBLIC KEY]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        Ed25519Identity, X25519Identity, encryption_key_rotation_statement,
        verify_browser_pairing_state, verify_encryption_key_rotation, verify_profile_binding,
    };
    use crate::EncryptionIdentity;

    #[test]
    fn identities_have_redacted_debug_output() {
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("X25519");
        let signing = Ed25519Identity::from_seed(vec![9; 32]).expect("Ed25519");
        let output = format!("{encryption:?} {signing:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("7, 7"));
        assert!(!output.contains("9, 9"));
    }

    #[test]
    fn browser_pairing_state_has_a_dedicated_authenticated_domain() {
        let signing = Ed25519Identity::from_seed(vec![9; 32]).expect("Ed25519");
        let state = b"canonical pairing state";
        let signature = signing.sign_browser_pairing_state(state);

        verify_browser_pairing_state(signing.public_key(), state, &signature)
            .expect("pairing signature");
        assert!(verify_profile_binding(signing.public_key(), state, &signature).is_err());
        assert!(verify_browser_pairing_state(signing.public_key(), b"other", &signature).is_err());
    }

    #[test]
    fn encryption_key_rotation_statement_is_explicit_and_domain_separated() {
        let signing = Ed25519Identity::from_seed(vec![9; 32]).expect("Ed25519");
        let previous = EncryptionIdentity::from_legacy_storage(vec![7; 32]).expect("previous");
        let next = EncryptionIdentity::generate().expect("next");
        let (previous_key, next_key) =
            (previous.recipient_public_key(), next.recipient_public_key());
        let agent_id = [0x55; 16];
        let statement = encryption_key_rotation_statement(&agent_id, &previous_key, &next_key);
        assert!(statement.starts_with(b"palladin.agent-encryption-key-rotation.v1\0\0\x02"));
        assert_eq!(statement.len(), 42 + 2 + 16 + 32 + 2 + 17 + 32);
        let signature = signing.sign_encryption_key_rotation(&agent_id, &previous, &next);
        verify_encryption_key_rotation(
            signing.public_key(),
            &agent_id,
            &previous_key,
            &next_key,
            &signature,
        )
        .expect("rotation signature");
        assert!(
            verify_profile_binding(signing.public_key(), &statement[42..], &signature).is_err()
        );
        for (agent, previous, next) in [
            (&[0x56; 16], &previous_key, &next_key),
            (&agent_id, &next_key, &previous_key),
        ] {
            assert!(
                verify_encryption_key_rotation(
                    signing.public_key(),
                    agent,
                    previous,
                    next,
                    &signature
                )
                .is_err()
            );
        }
    }

    #[test]
    fn libsodium_signing_secret_round_trips() {
        let identity = Ed25519Identity::from_seed(vec![11; 32]).expect("identity");
        let stored = identity.libsodium_secret_for_secure_storage();
        let restored = Ed25519Identity::from_libsodium_secret(stored.expose_secret().to_vec())
            .expect("restore");
        assert_eq!(restored.public_key(), identity.public_key());
    }

    #[test]
    fn profile_binding_signature_is_domain_specific_and_detects_tampering() {
        let identity = Ed25519Identity::from_seed(vec![17; 32]).expect("identity");
        let signature = identity.sign_profile_binding(b"canonical-binding");
        verify_profile_binding(identity.public_key(), b"canonical-binding", &signature)
            .expect("valid signature");
        assert!(
            verify_profile_binding(identity.public_key(), b"tampered-binding", &signature).is_err()
        );
    }
}
