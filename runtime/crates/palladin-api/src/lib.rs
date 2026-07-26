#![forbid(unsafe_code)]

mod client;
mod types;

pub use client::{ApiClient, ApiError, SigningContext};
pub use types::{
    AgentRegistrationResult, AgentVaultDiscoveryEnvelope, AgentVaultManifestItem,
    AgentVaultManifestsResponse, AgentVisibleField, CredentialAccess, CredentialMethod,
    EntrySearchItem, EntrySearchResult, GetCredentialOptions, GrantStatus, GrantStatusResponse,
    InjectFailureUpload, ReportCredentialStaleInput, StaleReasonCode, VaultManifest,
};
