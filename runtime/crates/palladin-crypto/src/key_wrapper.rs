//! Algorithm-neutral key wrapper (`palladin-protocol` contracts/key-wrapper/v1).
//!
//! Product code handles only suite ids, recipient key kinds and opaque package bytes. Every
//! algorithm detail is resolved here from a fixed, build-time registry.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretBox, SecretSlice};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, EnvelopeScope,
    suite::{
        SCOPE_AGENT, SCOPE_ENTRY, SCOPE_GRANT_OR_REQUEST, SCOPE_MEMBER, SCOPE_ORGANIZATION,
        SCOPE_VAULT, push_u16, push_u32, push_u64,
    },
    xwing,
};

pub const PROTOCOL_VERSION: u16 = 2;
const KEY_BYTES: usize = 32;
const CONTEXT_MAGIC: &[u8; 8] = b"PLDNX2W1";
const CONTEXT_HASH_DOMAIN: &[u8; 9] = b"PLDNX2CTX";
const FINGERPRINT_DOMAIN: &[u8; 8] = b"PLDNV2FP";
const X25519_PACKAGE_MAGIC: &[u8; 8] = b"PLDNX2K1";
const X25519_PLAINTEXT_BYTES: usize = 72;
const X25519_PACKAGE_BYTES: usize = 120;
const XWING_KDF_LABEL: &[u8; 10] = b"PLDNXW1KEY";
const XWING_AAD_LABEL: &[u8; 10] = b"PLDNXW1AAD";
const XWING_PACKAGE_BYTES: usize = xwing::CIPHERTEXT_BYTES + KEY_BYTES + 16;
const STORAGE_MAGIC: &[u8; 8] = b"PLDNEK01";
const SELF_SEAL_LABEL: &[u8; 10] = b"PLDNXW1BOX";

/// Contract error codes of key-wrapper v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WrapperError {
    #[error("unsupported-suite")]
    UnsupportedSuite,
    #[error("suite-not-allowed-for-purpose")]
    SuiteNotAllowedForPurpose,
    #[error("suite-not-writable")]
    SuiteNotWritable,
    #[error("unsupported-purpose")]
    UnsupportedPurpose,
    #[error("malformed-descriptor")]
    MalformedDescriptor,
    #[error("malformed-package")]
    MalformedPackage,
    #[error("recipient-mismatch")]
    RecipientMismatch,
    #[error("open-failed")]
    OpenFailed,
}

impl WrapperError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSuite => "unsupported-suite",
            Self::SuiteNotAllowedForPurpose => "suite-not-allowed-for-purpose",
            Self::SuiteNotWritable => "suite-not-writable",
            Self::UnsupportedPurpose => "unsupported-purpose",
            Self::MalformedDescriptor => "malformed-descriptor",
            Self::MalformedPackage => "malformed-package",
            Self::RecipientMismatch => "recipient-mismatch",
            Self::OpenFailed => "open-failed",
        }
    }
}

impl From<WrapperError> for CryptoError {
    fn from(error: WrapperError) -> Self {
        match error {
            WrapperError::UnsupportedSuite | WrapperError::SuiteNotWritable => {
                Self::UnsupportedSuite
            }
            WrapperError::SuiteNotAllowedForPurpose
            | WrapperError::UnsupportedPurpose
            | WrapperError::MalformedDescriptor => Self::InvalidDescriptor,
            WrapperError::MalformedPackage => Self::InvalidLength,
            WrapperError::RecipientMismatch | WrapperError::OpenFailed => {
                Self::AuthenticationFailed
            }
        }
    }
}

/// Wrapper suites compiled into this release. There is no runtime registration or negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapperSuite {
    XWingV1,
    X25519SealedBoxV1,
}

impl WrapperSuite {
    const REGISTERED: [Self; 2] = [Self::XWingV1, Self::X25519SealedBoxV1];
    /// The suite of publications and envelopes that predate suite fields.
    pub(crate) const LEGACY: Self = Self::X25519SealedBoxV1;

    pub fn from_id(id: &str) -> Result<Self, WrapperError> {
        Self::REGISTERED
            .into_iter()
            .find(|suite| suite.id() == id)
            .ok_or(WrapperError::UnsupportedSuite)
    }

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::XWingV1 => "palladin-xwing-v1",
            Self::X25519SealedBoxV1 => "palladin-x25519-sealed-box-v1",
        }
    }

    /// Only `active` suites seal; `read-only` suites are opened while old envelopes are migrated.
    #[must_use]
    pub const fn can_seal(self) -> bool {
        matches!(self, Self::XWingV1)
    }

    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::XWingV1 => xwing::PUBLIC_KEY_BYTES,
            Self::X25519SealedBoxV1 => 32,
        }
    }

    pub(crate) const fn package_bytes(self) -> usize {
        match self {
            Self::XWingV1 => XWING_PACKAGE_BYTES,
            Self::X25519SealedBoxV1 => X25519_PACKAGE_BYTES,
        }
    }

    const fn allows_purpose(self, _purpose: WrapperPurpose) -> bool {
        // Both registered suites currently serve every purpose 1..=9.
        true
    }

    /// Suite fingerprint of an authenticated recipient public key.
    pub fn fingerprint(
        self,
        public_key: &[u8],
        key_kind: RecipientKeyKind,
    ) -> Result<[u8; 32], WrapperError> {
        if public_key.len() != self.public_key_bytes() {
            return Err(WrapperError::RecipientMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(PROTOCOL_VERSION.to_be_bytes());
        hasher.update((key_kind as u16).to_be_bytes());
        // The frozen legacy suite keeps its suite-less fingerprint so existing ones stay valid.
        if self != Self::X25519SealedBoxV1 {
            hasher.update((self.id().len() as u16).to_be_bytes());
            hasher.update(self.id().as_bytes());
        }
        hasher.update(public_key);
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WrapperPurpose {
    MemberVaultKey = 1,
    AgentVdk = 2,
    ReasonDek = 3,
    GrantDek = 4,
    AgentVaultKey = 5,
    ScriptExecutionDek = 6,
    SubmissionDek = 7,
    ApproverMessagePrivateKey = 8,
    ApproverSigningPrivateKey = 9,
}

impl WrapperPurpose {
    pub fn from_code(code: u16) -> Result<Self, WrapperError> {
        Ok(match code {
            1 => Self::MemberVaultKey,
            2 => Self::AgentVdk,
            3 => Self::ReasonDek,
            4 => Self::GrantDek,
            5 => Self::AgentVaultKey,
            6 => Self::ScriptExecutionDek,
            7 => Self::SubmissionDek,
            8 => Self::ApproverMessagePrivateKey,
            9 => Self::ApproverSigningPrivateKey,
            _ => return Err(WrapperError::UnsupportedPurpose),
        })
    }

    const fn rule(self) -> PurposeRule {
        use Presence::{Forbidden, Optional, Required};
        use RecipientKeyKind::{
            AgentEncryption, MemberEncryption, OrganizationApproverMessage, VaultAgentMessage,
        };
        const ENTRY_AGENT: u16 =
            SCOPE_ORGANIZATION | SCOPE_VAULT | SCOPE_ENTRY | SCOPE_GRANT_OR_REQUEST | SCOPE_AGENT;
        match self {
            Self::MemberVaultKey => PurposeRule {
                scope: SCOPE_ORGANIZATION | SCOPE_VAULT | SCOPE_MEMBER,
                recipient_key_kinds: &[MemberEncryption],
                member_key_generation: Required,
                parent_descriptor_hash: Forbidden,
            },
            Self::AgentVdk => PurposeRule {
                scope: SCOPE_ORGANIZATION | SCOPE_VAULT | SCOPE_AGENT,
                recipient_key_kinds: &[AgentEncryption],
                member_key_generation: Optional,
                parent_descriptor_hash: Forbidden,
            },
            Self::ReasonDek => PurposeRule {
                scope: ENTRY_AGENT,
                recipient_key_kinds: &[VaultAgentMessage],
                member_key_generation: Optional,
                parent_descriptor_hash: Required,
            },
            Self::GrantDek => PurposeRule {
                scope: ENTRY_AGENT,
                recipient_key_kinds: &[AgentEncryption],
                member_key_generation: Optional,
                parent_descriptor_hash: Required,
            },
            Self::AgentVaultKey => PurposeRule {
                scope: SCOPE_ORGANIZATION | SCOPE_VAULT | SCOPE_GRANT_OR_REQUEST | SCOPE_AGENT,
                recipient_key_kinds: &[AgentEncryption],
                member_key_generation: Forbidden,
                parent_descriptor_hash: Forbidden,
            },
            Self::ScriptExecutionDek => PurposeRule {
                scope: ENTRY_AGENT,
                recipient_key_kinds: &[AgentEncryption],
                member_key_generation: Forbidden,
                parent_descriptor_hash: Required,
            },
            Self::SubmissionDek => PurposeRule {
                scope: SCOPE_ORGANIZATION | SCOPE_GRANT_OR_REQUEST | SCOPE_AGENT,
                recipient_key_kinds: &[AgentEncryption, OrganizationApproverMessage],
                member_key_generation: Forbidden,
                parent_descriptor_hash: Required,
            },
            Self::ApproverMessagePrivateKey | Self::ApproverSigningPrivateKey => PurposeRule {
                scope: SCOPE_ORGANIZATION | SCOPE_MEMBER,
                recipient_key_kinds: &[MemberEncryption],
                member_key_generation: Forbidden,
                parent_descriptor_hash: Forbidden,
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Presence {
    Required,
    Optional,
    Forbidden,
}

impl Presence {
    const fn accepts(self, present: bool) -> bool {
        match self {
            Self::Required => present,
            Self::Optional => true,
            Self::Forbidden => !present,
        }
    }
}

struct PurposeRule {
    scope: u16,
    recipient_key_kinds: &'static [RecipientKeyKind],
    member_key_generation: Presence,
    parent_descriptor_hash: Presence,
}

/// Registered key kinds. Signing kinds are fingerprinted but never wrapper recipients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecipientKeyKind {
    AgentEncryption = 1,
    AgentSigning = 2,
    VaultSigning = 3,
    VaultAgentMessage = 4,
    MemberEncryption = 5,
    OrganizationApproverMessage = 6,
    OrganizationApproverSigning = 7,
}

impl RecipientKeyKind {
    pub fn from_code(code: u16) -> Result<Self, WrapperError> {
        Ok(match code {
            1 => Self::AgentEncryption,
            2 => Self::AgentSigning,
            3 => Self::VaultSigning,
            4 => Self::VaultAgentMessage,
            5 => Self::MemberEncryption,
            6 => Self::OrganizationApproverMessage,
            7 => Self::OrganizationApproverSigning,
            _ => return Err(WrapperError::MalformedDescriptor),
        })
    }
}

/// Fingerprint of a 32-byte signing key (Ed25519 Vault, Agent and approver signing keys).
#[must_use]
pub fn compute_key_fingerprint(public_key: &[u8; 32], key_kind: RecipientKeyKind) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update((key_kind as u16).to_be_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

/// The descriptor of one wrapper, built by the caller from authenticated state before opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapperContext {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    pub purpose: WrapperPurpose,
    /// Scopes outside the purpose bitmap must be absent; an absent Vault is the zero UUID.
    pub scope: EnvelopeScope,
    pub resource_revision: u64,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    pub recipient_key_kind: RecipientKeyKind,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: [u8; 32],
    pub parent_descriptor_hash: Option<[u8; 32]>,
}

impl WrapperContext {
    /// Resolves the suite for `operation`, then validates the descriptor against its purpose.
    fn resolve(&self, seal: bool) -> Result<WrapperSuite, WrapperError> {
        let suite = WrapperSuite::from_id(&self.wrapper_suite_id)?;
        if seal && !suite.can_seal() {
            return Err(WrapperError::SuiteNotWritable);
        }
        if !suite.allows_purpose(self.purpose) {
            return Err(WrapperError::SuiteNotAllowedForPurpose);
        }
        self.validate()?;
        Ok(suite)
    }

    fn validate(&self) -> Result<(), WrapperError> {
        let rule = self.purpose.rule();
        if self.protocol_version != PROTOCOL_VERSION
            || self.resource_revision == 0
            || self.wrapped_key_version == 0
            || self.recipient_key_version == 0
            || self.member_key_generation == Some(0)
            || self.scope.organization_id == [0; 16]
            || self.scope_bitmap() != rule.scope
            || (rule.scope & SCOPE_VAULT == 0) != (self.scope.vault_id == [0; 16])
            || !rule
                .member_key_generation
                .accepts(self.member_key_generation.is_some())
            || !rule
                .parent_descriptor_hash
                .accepts(self.parent_descriptor_hash.is_some())
            || !rule.recipient_key_kinds.contains(&self.recipient_key_kind)
        {
            return Err(WrapperError::MalformedDescriptor);
        }
        Ok(())
    }

    fn scope_bitmap(&self) -> u16 {
        SCOPE_ORGANIZATION
            | if self.scope.vault_id == [0; 16] {
                0
            } else {
                SCOPE_VAULT
            }
            | self.scope.entry_id.map_or(0, |_| SCOPE_ENTRY)
            | self
                .scope
                .grant_or_request_id
                .map_or(0, |_| SCOPE_GRANT_OR_REQUEST)
            | self.scope.agent_id.map_or(0, |_| SCOPE_AGENT)
            | self.scope.member_id.map_or(0, |_| SCOPE_MEMBER)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.resolve(false)?;
        Ok(self.encode())
    }

    fn encode(&self) -> Vec<u8> {
        let bitmap = self.scope_bitmap();
        let suite = self.wrapper_suite_id.as_bytes();
        let mut encoded = Vec::with_capacity(192);
        encoded.extend_from_slice(CONTEXT_MAGIC);
        push_u16(&mut encoded, self.protocol_version);
        push_u16(&mut encoded, suite.len() as u16);
        encoded.extend_from_slice(suite);
        push_u16(&mut encoded, self.purpose as u16);
        push_u16(&mut encoded, bitmap);
        let scope = &self.scope;
        let ids = [
            (SCOPE_ORGANIZATION, Some(scope.organization_id)),
            (SCOPE_VAULT, Some(scope.vault_id)),
            (SCOPE_ENTRY, scope.entry_id),
            (SCOPE_GRANT_OR_REQUEST, scope.grant_or_request_id),
            (SCOPE_AGENT, scope.agent_id),
            (SCOPE_MEMBER, scope.member_id),
        ];
        for (bit, id) in ids {
            if let Some(id) = id.filter(|_| bitmap & bit != 0) {
                encoded.extend_from_slice(&id);
            }
        }
        push_u64(&mut encoded, self.resource_revision);
        push_u32(&mut encoded, self.wrapped_key_version);
        match self.member_key_generation {
            Some(generation) => {
                encoded.push(1);
                push_u32(&mut encoded, generation);
            }
            None => encoded.push(0),
        }
        push_u16(&mut encoded, self.recipient_key_kind as u16);
        push_u32(&mut encoded, self.recipient_key_version);
        encoded.extend_from_slice(&self.recipient_fingerprint);
        match self.parent_descriptor_hash {
            Some(hash) => {
                encoded.push(1);
                encoded.extend_from_slice(&hash);
            }
            None => encoded.push(0),
        }
        encoded
    }

    fn context_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_HASH_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }

    /// `recipient_suite` comes from the recipient key's authenticated directory entry, never from
    /// the envelope; a mismatch with the descriptor suite is a substitution attempt.
    fn bind_recipient(
        &self,
        suite: WrapperSuite,
        recipient_suite: WrapperSuite,
        public_key: &[u8],
    ) -> Result<(), WrapperError> {
        if recipient_suite != suite {
            return Err(WrapperError::RecipientMismatch);
        }
        let fingerprint = suite.fingerprint(public_key, self.recipient_key_kind)?;
        if fingerprint.ct_eq(&self.recipient_fingerprint).unwrap_u8() != 1 {
            return Err(WrapperError::RecipientMismatch);
        }
        Ok(())
    }

    /// Seals `key` with an active suite to an authenticated recipient public key.
    pub fn seal(
        &self,
        key: &SecretBox<[u8; KEY_BYTES]>,
        recipient: &RecipientPublicKey,
    ) -> Result<SealedWrappedKey, WrapperError> {
        let suite = self.resolve(true)?;
        self.bind_recipient(suite, recipient.suite, &recipient.bytes)?;
        let mut randomness = Zeroizing::new([0_u8; xwing::ENCAPSULATION_RANDOMNESS_BYTES]);
        getrandom::fill(randomness.as_mut()).map_err(|_| WrapperError::OpenFailed)?;
        let package = match suite {
            WrapperSuite::XWingV1 => {
                seal_xwing(key, &recipient.bytes, &self.context_hash(), &randomness)?
            }
            WrapperSuite::X25519SealedBoxV1 => return Err(WrapperError::SuiteNotWritable),
        };
        Ok(SealedWrappedKey(package))
    }

    /// Opens a package with the recipient's own key after rebuilding the context from
    /// authenticated state.
    pub fn open(
        &self,
        package: &[u8],
        recipient: &EncryptionIdentity,
    ) -> Result<SecretBox<[u8; KEY_BYTES]>, WrapperError> {
        self.open_classified(package, recipient)
            .map_err(|error| match error {
                OpenError::Wrapper(error) => error,
                OpenError::ContextMismatch => WrapperError::OpenFailed,
            })
    }

    /// Same as `open`, but reports a legacy package that opened under a different context
    /// separately, as the frozen agent-submission v1 error codes require. X-Wing binds the
    /// context into its key derivation, so it can only report `open-failed`.
    pub(crate) fn open_classified(
        &self,
        package: &[u8],
        recipient: &EncryptionIdentity,
    ) -> Result<SecretBox<[u8; KEY_BYTES]>, OpenError> {
        let suite = self.resolve(false)?;
        self.bind_recipient(suite, recipient.suite, &recipient.public_key)?;
        if package.len() != suite.package_bytes() {
            return Err(WrapperError::MalformedPackage.into());
        }
        let expected_hash = self.context_hash();
        match suite {
            WrapperSuite::XWingV1 => Ok(open_xwing(package, recipient, &expected_hash)?),
            WrapperSuite::X25519SealedBoxV1 => open_x25519(package, recipient, &expected_hash),
        }
    }
}

fn xwing_aead_key(
    shared: &[u8; 32],
    context_hash: &[u8; 32],
    public_key: &[u8],
    kem_ciphertext: &[u8],
) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut info = Vec::with_capacity(XWING_KDF_LABEL.len() + 96);
    info.extend_from_slice(XWING_KDF_LABEL);
    info.extend_from_slice(context_hash);
    info.extend_from_slice(&Sha256::digest(public_key));
    info.extend_from_slice(&Sha256::digest(kem_ciphertext));
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(&info, key.as_mut())
        .expect("32-byte HKDF output");
    key
}

fn xwing_aad(context_hash: &[u8; 32]) -> [u8; 42] {
    let mut aad = [0_u8; 42];
    aad[..10].copy_from_slice(XWING_AAD_LABEL);
    aad[10..].copy_from_slice(context_hash);
    aad
}

fn seal_xwing(
    key: &SecretBox<[u8; KEY_BYTES]>,
    public_key: &[u8],
    context_hash: &[u8; 32],
    randomness: &[u8; xwing::ENCAPSULATION_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, WrapperError> {
    let public_key: &[u8; xwing::PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| WrapperError::RecipientMismatch)?;
    let (kem_ciphertext, shared) =
        xwing::encapsulate(public_key, randomness).ok_or(WrapperError::RecipientMismatch)?;
    let aead_key = xwing_aead_key(&shared, context_hash, public_key, &kem_ciphertext);
    // A zero nonce is safe only because every encapsulation yields a fresh single-use key.
    let sealed = XChaCha20Poly1305::new(aead_key.as_ref().into())
        .encrypt(
            &XNonce::default(),
            Payload {
                msg: key.expose_secret(),
                aad: &xwing_aad(context_hash),
            },
        )
        .map_err(|_| WrapperError::OpenFailed)?;
    let mut package = Vec::with_capacity(XWING_PACKAGE_BYTES);
    package.extend_from_slice(&kem_ciphertext);
    package.extend_from_slice(&sealed);
    Ok(package)
}

fn open_xwing(
    package: &[u8],
    recipient: &EncryptionIdentity,
    context_hash: &[u8; 32],
) -> Result<SecretBox<[u8; KEY_BYTES]>, WrapperError> {
    let (kem_ciphertext, sealed) = package.split_at(xwing::CIPHERTEXT_BYTES);
    let seed: &[u8; xwing::SEED_BYTES] = recipient
        .private_key
        .expose_secret()
        .try_into()
        .map_err(|_| WrapperError::RecipientMismatch)?;
    let shared = xwing::ExpandedKey::from_seed(seed).decapsulate(
        kem_ciphertext
            .try_into()
            .map_err(|_| WrapperError::MalformedPackage)?,
    );
    let aead_key = xwing_aead_key(&shared, context_hash, &recipient.public_key, kem_ciphertext);
    let opened = Zeroizing::new(
        XChaCha20Poly1305::new(aead_key.as_ref().into())
            .decrypt(
                &XNonce::default(),
                Payload {
                    msg: sealed,
                    aad: &xwing_aad(context_hash),
                },
            )
            .map_err(|_| WrapperError::OpenFailed)?,
    );
    let key: [u8; KEY_BYTES] = opened
        .as_slice()
        .try_into()
        .map_err(|_| WrapperError::OpenFailed)?;
    Ok(SecretBox::new(Box::new(key)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenError {
    Wrapper(WrapperError),
    ContextMismatch,
}

impl From<WrapperError> for OpenError {
    fn from(error: WrapperError) -> Self {
        Self::Wrapper(error)
    }
}

fn open_x25519(
    package: &[u8],
    recipient: &EncryptionIdentity,
    context_hash: &[u8; 32],
) -> Result<SecretBox<[u8; KEY_BYTES]>, OpenError> {
    let private_key: [u8; 32] = recipient
        .private_key
        .expose_secret()
        .try_into()
        .map_err(|_| WrapperError::RecipientMismatch)?;
    let secret = crypto_box::SecretKey::from_bytes(private_key);
    let plaintext = Zeroizing::new(
        secret
            .unseal(package)
            .map_err(|_| WrapperError::OpenFailed)?,
    );
    if plaintext.len() != X25519_PLAINTEXT_BYTES
        || plaintext[..8].ct_eq(X25519_PACKAGE_MAGIC).unwrap_u8() != 1
    {
        return Err(WrapperError::OpenFailed.into());
    }
    if plaintext[40..].ct_eq(context_hash).unwrap_u8() != 1 {
        return Err(OpenError::ContextMismatch);
    }
    let key: [u8; KEY_BYTES] = plaintext[8..40]
        .try_into()
        .map_err(|_| WrapperError::OpenFailed)?;
    Ok(SecretBox::new(Box::new(key)))
}

/// Anonymous public-key encryption of local data to the Agent's own key (the suite's
/// analogue of a sealed box). Callers bind context inside the plaintext.
pub(crate) fn seal_to_self(
    recipient: &RecipientPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match recipient.suite {
        WrapperSuite::X25519SealedBoxV1 => {
            let public_key: [u8; 32] = recipient
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidLength)?;
            crypto_box::PublicKey::from(public_key)
                .seal(&mut OsRng, plaintext)
                .map_err(|_| CryptoError::AuthenticationFailed)
        }
        WrapperSuite::XWingV1 => {
            let public_key: &[u8; xwing::PUBLIC_KEY_BYTES] = recipient
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidLength)?;
            let mut randomness = Zeroizing::new([0_u8; xwing::ENCAPSULATION_RANDOMNESS_BYTES]);
            getrandom::fill(randomness.as_mut())
                .map_err(|_| CryptoError::RandomGenerationFailed)?;
            let (kem_ciphertext, shared) =
                xwing::encapsulate(public_key, &randomness).ok_or(CryptoError::InvalidEncoding)?;
            let key = self_seal_key(&shared, public_key, &kem_ciphertext);
            let sealed = XChaCha20Poly1305::new(key.as_ref().into())
                .encrypt(&XNonce::default(), plaintext)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            let mut output = Vec::with_capacity(kem_ciphertext.len() + sealed.len());
            output.extend_from_slice(&kem_ciphertext);
            output.extend_from_slice(&sealed);
            Ok(output)
        }
    }
}

pub(crate) const SELF_SEAL_OVERHEAD_BYTES: usize = 48;
pub(crate) const MAX_SELF_SEAL_OVERHEAD_BYTES: usize = xwing::CIPHERTEXT_BYTES + 16;

fn self_seal_key(
    shared: &[u8; 32],
    public_key: &[u8],
    kem_ciphertext: &[u8],
) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut info = Vec::with_capacity(SELF_SEAL_LABEL.len() + 64);
    info.extend_from_slice(SELF_SEAL_LABEL);
    info.extend_from_slice(&Sha256::digest(public_key));
    info.extend_from_slice(&Sha256::digest(kem_ciphertext));
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(&info, key.as_mut())
        .expect("32-byte HKDF output");
    key
}

impl EncryptionIdentity {
    pub(crate) fn open_sealed_to_self(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self.suite {
            WrapperSuite::X25519SealedBoxV1 => {
                let private_key: [u8; 32] = self
                    .private_key
                    .expose_secret()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidLength)?;
                crypto_box::SecretKey::from_bytes(private_key)
                    .unseal(ciphertext)
                    .map(Zeroizing::new)
                    .map_err(|_| CryptoError::AuthenticationFailed)
            }
            WrapperSuite::XWingV1 => {
                if ciphertext.len() < MAX_SELF_SEAL_OVERHEAD_BYTES {
                    return Err(CryptoError::AuthenticationFailed);
                }
                let (kem_ciphertext, sealed) = ciphertext.split_at(xwing::CIPHERTEXT_BYTES);
                let seed: &[u8; xwing::SEED_BYTES] = self
                    .private_key
                    .expose_secret()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidLength)?;
                let shared = xwing::ExpandedKey::from_seed(seed).decapsulate(
                    kem_ciphertext
                        .try_into()
                        .map_err(|_| CryptoError::InvalidLength)?,
                );
                let key = self_seal_key(&shared, &self.public_key, kem_ciphertext);
                XChaCha20Poly1305::new(key.as_ref().into())
                    .decrypt(&XNonce::default(), sealed)
                    .map(Zeroizing::new)
                    .map_err(|_| CryptoError::AuthenticationFailed)
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealedWrappedKey(Vec<u8>);

impl SealedWrappedKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SealedWrappedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedWrappedKey")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A recipient public key together with the suite registered for it in its authenticated
/// key directory.
#[derive(Clone, Eq, PartialEq)]
pub struct RecipientPublicKey {
    suite: WrapperSuite,
    bytes: Vec<u8>,
}

impl RecipientPublicKey {
    pub fn new(suite_id: &str, bytes: Vec<u8>) -> Result<Self, WrapperError> {
        let suite = WrapperSuite::from_id(suite_id)?;
        if bytes.len() != suite.public_key_bytes() {
            return Err(WrapperError::RecipientMismatch);
        }
        Ok(Self { suite, bytes })
    }

    /// A key from its signed publication. Publications that predate suite fields (vault-v2
    /// manifests, approver manifest v1, Agent submission v1) carry the legacy suite.
    pub fn from_publication(suite_id: Option<&str>, bytes: Vec<u8>) -> Result<Self, WrapperError> {
        Self::new(suite_id.unwrap_or(WrapperSuite::LEGACY.id()), bytes)
    }

    /// False for a key whose suite is read-only: its owner must publish a current key before
    /// anything can be sealed to it (`key-migration-pending`).
    #[must_use]
    pub fn can_seal(&self) -> bool {
        self.suite.can_seal()
    }

    #[must_use]
    pub fn suite_id(&self) -> &'static str {
        self.suite.id()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn fingerprint(&self, key_kind: RecipientKeyKind) -> [u8; 32] {
        self.suite
            .fingerprint(&self.bytes, key_kind)
            .expect("length validated at construction")
    }
}

impl std::fmt::Debug for RecipientPublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecipientPublicKey")
            .field("suite", &self.suite.id())
            .finish_non_exhaustive()
    }
}

/// A locally held wrapper recipient key. The private key is the suite's compact seed and is
/// never expanded outside one operation.
pub struct EncryptionIdentity {
    suite: WrapperSuite,
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl EncryptionIdentity {
    /// Generates a key for the active suite.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new(vec![0_u8; xwing::SEED_BYTES]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Self::from_private_key(WrapperSuite::XWingV1, seed.to_vec())
    }

    fn from_private_key(
        suite: WrapperSuite,
        mut private_key: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let Ok(seed) = <[u8; 32]>::try_from(private_key.as_slice()) else {
            private_key.zeroize();
            return Err(CryptoError::InvalidLength);
        };
        let seed = Zeroizing::new(seed);
        let public_key = match suite {
            WrapperSuite::XWingV1 => xwing::ExpandedKey::from_seed(&seed).public_key().to_vec(),
            WrapperSuite::X25519SealedBoxV1 => {
                let secret = Zeroizing::new(StaticSecret::from(*seed));
                X25519PublicKey::from(&*secret).to_bytes().to_vec()
            }
        };
        Ok(Self {
            suite,
            private_key: private_key.into(),
            public_key,
        })
    }

    /// Loads the raw 32-byte key stored by releases that predate suite identifiers.
    pub fn from_legacy_storage(private_key: Vec<u8>) -> Result<Self, CryptoError> {
        Self::from_private_key(WrapperSuite::X25519SealedBoxV1, private_key)
    }

    /// Self-describing storage form: magic, suite id and private key seed.
    pub fn from_secure_storage(stored: &[u8]) -> Result<Self, CryptoError> {
        let suite_len = usize::from(*stored.get(8).ok_or(CryptoError::InvalidEncoding)?);
        if stored.len() != 9 + suite_len + 32 || &stored[..8] != STORAGE_MAGIC {
            return Err(CryptoError::InvalidEncoding);
        }
        let suite_id = std::str::from_utf8(&stored[9..9 + suite_len])
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let suite = WrapperSuite::from_id(suite_id).map_err(|_| CryptoError::UnsupportedSuite)?;
        Self::from_private_key(suite, stored[9 + suite_len..].to_vec())
    }

    #[must_use]
    pub fn secure_storage_bytes(&self) -> SecretSlice<u8> {
        let suite = self.suite.id().as_bytes();
        let mut stored = Vec::with_capacity(9 + suite.len() + 32);
        stored.extend_from_slice(STORAGE_MAGIC);
        stored.push(suite.len() as u8);
        stored.extend_from_slice(suite);
        stored.extend_from_slice(self.private_key.expose_secret());
        stored.into()
    }

    /// Raw private key for the legacy storage slot; only legacy-suite keys live there.
    pub fn legacy_storage_bytes(&self) -> Result<&[u8], CryptoError> {
        if self.suite != WrapperSuite::X25519SealedBoxV1 {
            return Err(CryptoError::UnsupportedSuite);
        }
        Ok(self.private_key.expose_secret())
    }

    #[must_use]
    pub fn suite_id(&self) -> &'static str {
        self.suite.id()
    }

    #[must_use]
    pub fn is_current_suite(&self) -> bool {
        self.suite.can_seal()
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    #[must_use]
    pub fn recipient_public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey {
            suite: self.suite,
            bytes: self.public_key.clone(),
        }
    }

    #[must_use]
    pub fn fingerprint(&self, key_kind: RecipientKeyKind) -> [u8; 32] {
        self.suite
            .fingerprint(&self.public_key, key_kind)
            .expect("public key derived for its own suite")
    }
}

impl std::fmt::Debug for EncryptionIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptionIdentity")
            .field("suite", &self.suite.id())
            .field("private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The Agent's encryption keys: the current key and, during a suite migration, the previous one
/// that still opens envelopes not yet re-wrapped. The Agent's own signed profile is the
/// authenticated directory for both.
#[derive(Debug)]
pub struct AgentEncryptionKeys {
    current: EncryptionIdentity,
    previous: Option<EncryptionIdentity>,
}

impl AgentEncryptionKeys {
    pub fn new(
        current: EncryptionIdentity,
        previous: Option<EncryptionIdentity>,
    ) -> Result<Self, CryptoError> {
        if previous
            .as_ref()
            .is_some_and(|previous| previous.public_key == current.public_key)
        {
            return Err(CryptoError::InvalidProfile);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current(&self) -> &EncryptionIdentity {
        &self.current
    }

    #[must_use]
    pub fn previous(&self) -> Option<&EncryptionIdentity> {
        self.previous.as_ref()
    }

    #[must_use]
    pub fn into_parts(self) -> (EncryptionIdentity, Option<EncryptionIdentity>) {
        (self.current, self.previous)
    }

    pub fn iter(&self) -> impl Iterator<Item = &EncryptionIdentity> {
        std::iter::once(&self.current).chain(self.previous.as_ref())
    }

    /// Fingerprints of every held key, for bindings such as a Vault manifest that may still
    /// name the previous key until a member re-wraps for the current one.
    pub fn fingerprints(&self, key_kind: RecipientKeyKind) -> Vec<[u8; 32]> {
        self.iter().map(|key| key.fingerprint(key_kind)).collect()
    }

    /// Selects the held key named by an envelope descriptor. The suite registered with that key
    /// locally must equal the envelope's suite.
    pub fn select(
        &self,
        wrapper_suite_id: &str,
        key_kind: RecipientKeyKind,
        fingerprint: &[u8; 32],
    ) -> Result<&EncryptionIdentity, WrapperError> {
        let suite = WrapperSuite::from_id(wrapper_suite_id)?;
        let key = self.select_by_fingerprint(key_kind, fingerprint)?;
        if key.suite != suite {
            return Err(WrapperError::RecipientMismatch);
        }
        Ok(key)
    }

    /// For contracts whose envelope carries no suite id (script-execution v1, agent-submission
    /// v1): suite fingerprints are domain separated, so the fingerprint alone names one local
    /// key and its registered suite.
    pub fn select_by_fingerprint(
        &self,
        key_kind: RecipientKeyKind,
        fingerprint: &[u8; 32],
    ) -> Result<&EncryptionIdentity, WrapperError> {
        self.iter()
            .find(|key| key.fingerprint(key_kind).ct_eq(fingerprint).unwrap_u8() == 1)
            .ok_or(WrapperError::RecipientMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(value)
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn xwing_matches_the_draft_10_known_answer() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/key-wrapper/v1/vectors.json"
        ))
        .expect("vectors");
        let kat = &fixture["xwingKnownAnswer"];
        let field = |name: &str| kat[name].as_str().expect(name).to_owned();
        let seed = hex32(&field("seedHex"));
        let key = xwing::ExpandedKey::from_seed(&seed);
        assert_eq!(
            hex::encode(Sha256::digest(key.public_key())),
            field("publicKeySha256Hex")
        );
        assert!(hex::encode(key.public_key()).starts_with(&field("publicKeyPrefixHex")));
        let randomness: [u8; 64] = hex::decode(field("encapsulationRandomnessHex"))
            .expect("hex")
            .try_into()
            .expect("64 bytes");
        let (ciphertext, shared) =
            xwing::encapsulate(key.public_key(), &randomness).expect("valid key");
        assert_eq!(
            hex::encode(Sha256::digest(ciphertext)),
            field("ciphertextSha256Hex")
        );
        assert!(hex::encode(ciphertext).starts_with(&field("ciphertextPrefixHex")));
        assert_eq!(hex::encode(*shared), field("sharedSecretHex"));
        assert_eq!(
            hex::encode(*key.decapsulate(&ciphertext)),
            field("sharedSecretHex")
        );
    }

    #[test]
    fn storage_form_round_trips_and_rejects_unknown_suites() {
        let identity = EncryptionIdentity::generate().expect("identity");
        let stored = identity.secure_storage_bytes();
        let loaded = EncryptionIdentity::from_secure_storage(stored.expose_secret()).expect("load");
        assert_eq!(loaded.public_key(), identity.public_key());
        assert_eq!(loaded.suite_id(), "palladin-xwing-v1");
        assert_eq!(identity.public_key().len(), 1216);

        let mut tampered = stored.expose_secret().to_vec();
        tampered[9] = b'q';
        assert_eq!(
            EncryptionIdentity::from_secure_storage(&tampered).expect_err("unknown suite"),
            CryptoError::UnsupportedSuite
        );
        assert!(identity.legacy_storage_bytes().is_err());
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", &stored.expose_secret()[30..])));
    }

    #[test]
    fn keyring_selects_by_fingerprint_and_requires_the_registered_suite() {
        let current = EncryptionIdentity::generate().expect("current");
        let previous = EncryptionIdentity::from_legacy_storage(vec![7; 32]).expect("previous");
        let previous_fingerprint = previous.fingerprint(RecipientKeyKind::AgentEncryption);
        let keys = AgentEncryptionKeys::new(current, Some(previous)).expect("keys");
        let selected = keys
            .select(
                "palladin-x25519-sealed-box-v1",
                RecipientKeyKind::AgentEncryption,
                &previous_fingerprint,
            )
            .expect("legacy key");
        assert_eq!(selected.suite_id(), "palladin-x25519-sealed-box-v1");
        assert_eq!(
            keys.select(
                "palladin-xwing-v1",
                RecipientKeyKind::AgentEncryption,
                &previous_fingerprint
            )
            .expect_err("suite substitution"),
            WrapperError::RecipientMismatch
        );
        assert_eq!(
            keys.select(
                "palladin-xwing-v1",
                RecipientKeyKind::AgentEncryption,
                &[1; 32]
            )
            .expect_err("unknown key"),
            WrapperError::RecipientMismatch
        );
    }

    #[test]
    fn a_legacy_publication_is_never_sealed_to() {
        let recipient = EncryptionIdentity::from_legacy_storage(vec![7; 32]).expect("recipient");
        let context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: WrapperSuite::X25519SealedBoxV1.id().to_owned(),
            purpose: WrapperPurpose::ReasonDek,
            scope: EnvelopeScope {
                organization_id: [1; 16],
                vault_id: [2; 16],
                entry_id: Some([3; 16]),
                grant_or_request_id: Some([4; 16]),
                agent_id: Some([5; 16]),
                member_id: None,
            },
            resource_revision: 1,
            wrapped_key_version: 1,
            member_key_generation: None,
            recipient_key_kind: RecipientKeyKind::VaultAgentMessage,
            recipient_key_version: 1,
            recipient_fingerprint: recipient.fingerprint(RecipientKeyKind::VaultAgentMessage),
            parent_descriptor_hash: Some([6; 32]),
        };
        let public = RecipientPublicKey::from_publication(None, recipient.public_key().to_vec())
            .expect("legacy publication");
        assert!(!public.can_seal());
        assert_eq!(
            context
                .seal(&SecretBox::new(Box::new([9; 32])), &public)
                .expect_err("read-only suite"),
            WrapperError::SuiteNotWritable
        );
    }
}
