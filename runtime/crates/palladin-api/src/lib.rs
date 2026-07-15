#![forbid(unsafe_code)]

mod client;
mod types;

pub use client::{ApiClient, ApiError, SigningContext};
pub use types::{
    AgentRegistrationResult, AgentVisibleField, CredentialAccess, CredentialMethod,
    EntrySearchItem, EntrySearchResult, GetCredentialOptions, InjectFailureUpload,
    ReportCredentialStaleInput, StaleReasonCode,
};
