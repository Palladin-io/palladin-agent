#![forbid(unsafe_code)]

mod client;
mod types;

pub use client::{ApiClient, ApiError, SigningContext};
pub use types::{
    AgentDiscoveryDeltaResponse, AgentDiscoveryEnvelope, AgentDiscoveryEnvelopeHeader,
    AgentDiscoverySnapshotResponse, AgentDiscoverySyncItem, AgentPairingActivationResponse,
    AgentPairingStatus, AgentPairingStatusResponse, AgentRegistrationResult,
    AgentVaultDiscoveryEnvelope, AgentVaultManifestItem, AgentVaultManifestsResponse,
    AgentVisibleField, ApprovedCredentialMethods, CredentialAccess, CredentialMethod,
    EntrySearchItem, EntrySearchResult, GetCredentialOptions, GrantStatus, GrantStatusResponse,
    GrantedCredential, ReportCredentialStaleInput, StaleReasonCode, VaultManifest,
};
