#![forbid(unsafe_code)]

mod client;
mod types;

pub use client::{ApiClient, ApiError, BrowserPairingClient, SigningContext};
pub use palladin_browser_bridge::FormDiscoveryMap;
pub use types::{
    AgentDiscoveryDeltaResponse, AgentDiscoveryEnvelope, AgentDiscoveryEnvelopeDescriptor,
    AgentDiscoverySnapshotResponse, AgentDiscoverySyncItem, AgentPairingActivationResponse,
    AgentPairingStatus, AgentPairingStatusResponse, AgentRegistrationResult,
    AgentVaultDiscoveryEnvelope, AgentVaultManifestItem, AgentVaultManifestsResponse,
    AgentVisibleField, ApprovedCredentialMethods, BrowserPairingCredentialEnvelopeResponse,
    BrowserPairingStatusResponse, CredentialAccess, CredentialCiphertext, CredentialGrantType,
    CredentialMethod, EntrySearchItem, EntrySearchResult, EnvelopeScopeContract,
    GetCredentialOptions, GrantStatus, GrantStatusResponse, GrantedCredential,
    ReportCredentialStaleInput, ScriptExecutionDiscovery, ScriptExecutionPackageResponse,
    ScriptExecutionVaultEntry, StaleReasonCode, StartBrowserPairingResponse, VaultManifest,
    X25519WrappedKey, X25519WrapperDescriptor,
};
