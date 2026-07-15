#![forbid(unsafe_code)]

pub mod args;
pub mod output;

pub use palladin_core::terminal::{safe_terminal_text, shorten_identifier};
pub use palladin_runtime::{
    ConnectOutcome, CreatedProfile, CredentialDelivery, CredentialDeliveryRequest,
    CredentialExecOutcome, CredentialExecRequest, CredentialOutputPolicy, DeliveredCredential,
    InvocationSurface, LegacyCleanupOutcome, LegacyCutoverOutcome, OperationConnection,
    OperationDescriptor, OperatorOutput, RuntimeError, RuntimeService, RuntimeSession,
    StatusOutcome,
};
