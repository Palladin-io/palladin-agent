use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, SecretSlice};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

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

    use super::{Ed25519Identity, X25519Identity};

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
    fn libsodium_signing_secret_round_trips() {
        let identity = Ed25519Identity::from_seed(vec![11; 32]).expect("identity");
        let stored = identity.libsodium_secret_for_secure_storage();
        let restored = Ed25519Identity::from_libsodium_secret(stored.expose_secret().to_vec())
            .expect("restore");
        assert_eq!(restored.public_key(), identity.public_key());
    }
}
