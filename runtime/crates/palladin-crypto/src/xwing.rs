//! X-Wing hybrid KEM (ML-KEM-768 + X25519) pinned to draft-connolly-cfrg-xwing-kem-10.

use ml_kem::{
    B32, EncapsulationKey, MlKem768, Seed,
    array::Array,
    kem::{Decapsulate, KeyExport},
    ml_kem_768::{Ciphertext, DecapsulationKey},
};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

pub(crate) const SEED_BYTES: usize = 32;
pub(crate) const PUBLIC_KEY_BYTES: usize = 1216;
pub(crate) const CIPHERTEXT_BYTES: usize = 1120;
pub(crate) const ENCAPSULATION_RANDOMNESS_BYTES: usize = 64;
const ML_KEM_PUBLIC_KEY_BYTES: usize = 1184;
const ML_KEM_CIPHERTEXT_BYTES: usize = 1088;
const LABEL: &[u8; 6] = b"\\.//^\\";

pub(crate) struct ExpandedKey {
    ml_kem: DecapsulationKey,
    x25519_secret: Zeroizing<[u8; 32]>,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

impl ExpandedKey {
    /// The 32-byte seed is the only stored form; the expanded key exists only for one operation.
    pub(crate) fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        let mut expanded = Zeroizing::new([0_u8; 96]);
        let mut shake = Shake256::default();
        shake.update(seed);
        shake.finalize_xof().read(expanded.as_mut());
        let ml_kem_seed = Zeroizing::new(Seed::try_from(&expanded[..64]).expect("64-byte seed"));
        let ml_kem = DecapsulationKey::from_seed(*ml_kem_seed);
        let mut x25519_secret = Zeroizing::new([0_u8; 32]);
        x25519_secret.copy_from_slice(&expanded[64..]);
        let x25519_public = x25519(*x25519_secret, X25519_BASEPOINT_BYTES);
        let mut public_key = [0_u8; PUBLIC_KEY_BYTES];
        public_key[..ML_KEM_PUBLIC_KEY_BYTES]
            .copy_from_slice(&ml_kem.encapsulation_key().to_bytes());
        public_key[ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&x25519_public);
        Self {
            ml_kem,
            x25519_secret,
            public_key,
        }
    }

    pub(crate) fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    pub(crate) fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> Zeroizing<[u8; 32]> {
        let (ml_kem_ciphertext, x25519_ciphertext) = ciphertext.split_at(ML_KEM_CIPHERTEXT_BYTES);
        let ml_kem_ciphertext =
            Ciphertext::try_from(ml_kem_ciphertext).expect("fixed ML-KEM ciphertext length");
        let ml_kem_shared = Zeroizing::new(self.ml_kem.decapsulate(&ml_kem_ciphertext));
        let x25519_ciphertext: [u8; 32] = x25519_ciphertext
            .try_into()
            .expect("fixed X25519 ciphertext length");
        let x25519_shared = Zeroizing::new(x25519(*self.x25519_secret, x25519_ciphertext));
        combine(
            &ml_kem_shared,
            &x25519_shared,
            &x25519_ciphertext,
            self.public_key[ML_KEM_PUBLIC_KEY_BYTES..]
                .try_into()
                .expect("fixed X25519 public key length"),
        )
    }
}

/// Returns `None` for an encapsulation key that fails the FIPS 203 modulus check.
pub(crate) fn encapsulate(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    randomness: &[u8; ENCAPSULATION_RANDOMNESS_BYTES],
) -> Option<([u8; CIPHERTEXT_BYTES], Zeroizing<[u8; 32]>)> {
    let (ml_kem_public, x25519_public) = public_key.split_at(ML_KEM_PUBLIC_KEY_BYTES);
    let ml_kem_public = EncapsulationKey::<MlKem768>::new(
        &Array::try_from(ml_kem_public).expect("fixed ML-KEM public key length"),
    )
    .ok()?;
    let ml_kem_randomness = Zeroizing::new(B32::try_from(&randomness[..32]).expect("32 bytes"));
    let (ml_kem_ciphertext, ml_kem_shared) =
        ml_kem_public.encapsulate_deterministic(&ml_kem_randomness);
    let ml_kem_shared = Zeroizing::new(ml_kem_shared);
    let mut ephemeral = Zeroizing::new([0_u8; 32]);
    ephemeral.copy_from_slice(&randomness[32..]);
    let x25519_public: [u8; 32] = x25519_public
        .try_into()
        .expect("fixed X25519 public key length");
    let x25519_ciphertext = x25519(*ephemeral, X25519_BASEPOINT_BYTES);
    let x25519_shared = Zeroizing::new(x25519(*ephemeral, x25519_public));
    let shared = combine(
        &ml_kem_shared,
        &x25519_shared,
        &x25519_ciphertext,
        &x25519_public,
    );
    let mut ciphertext = [0_u8; CIPHERTEXT_BYTES];
    ciphertext[..ML_KEM_CIPHERTEXT_BYTES].copy_from_slice(&ml_kem_ciphertext);
    ciphertext[ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(&x25519_ciphertext);
    Some((ciphertext, shared))
}

fn combine(
    ml_kem_shared: &[u8],
    x25519_shared: &[u8; 32],
    x25519_ciphertext: &[u8; 32],
    x25519_public: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    for part in [
        ml_kem_shared,
        x25519_shared,
        x25519_ciphertext,
        x25519_public,
        LABEL.as_slice(),
    ] {
        Digest::update(&mut hasher, part);
    }
    Zeroizing::new(hasher.finalize().into())
}
