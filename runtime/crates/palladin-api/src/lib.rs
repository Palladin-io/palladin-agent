#![forbid(unsafe_code)]

mod client;
mod types;

pub use client::{ApiClient, ApiError, SigningContext};
pub use palladin_browser_bridge::FormDiscoveryMap;
pub use types::{
    AgentDiscoveryDeltaResponse, AgentDiscoveryEnvelope, AgentDiscoveryEnvelopeDescriptor,
    AgentDiscoverySnapshotResponse, AgentDiscoverySyncItem, AgentPairingActivationResponse,
    AgentPairingStatus, AgentPairingStatusResponse, AgentRegistrationResult,
    AgentVaultDiscoveryEnvelope, AgentVaultManifestItem, AgentVaultManifestsResponse,
    AgentVisibleField, ApprovedCredentialMethods, CredentialAccess, CredentialCiphertext,
    CredentialGrantType, CredentialMethod, EntrySearchItem, EntrySearchResult,
    EnvelopeScopeContract, GetCredentialOptions, GrantStatus, GrantStatusResponse,
    GrantedCredential, ReportCredentialStaleInput, ScriptExecutionDiscovery,
    ScriptExecutionPackageResponse, ScriptExecutionVaultEntry, StaleReasonCode, VaultManifest,
    X25519WrappedKey, X25519WrapperDescriptor,
};
