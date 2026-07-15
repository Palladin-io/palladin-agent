#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(windows, test))]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
mod windows;

pub const EXECUTOR_FILE_NAME: &str = "palladin-executor.exe";
pub const EXECUTOR_FAILURE_EXIT_CODE: i32 = 125;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
#[cfg(any(windows, test))]
const WINDOWS_EXECUTOR_PUBLIC_ENVIRONMENT: &[&str] = &[
    "LOCALAPPDATA",
    "PATH",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

#[cfg(any(windows, test))]
fn validate_windows_secret_environment_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), ExecutorError> {
    let mut unique = BTreeSet::new();
    for name in names {
        let mut bytes = name.bytes();
        let valid_start = bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic());
        if !valid_start
            || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            || WINDOWS_EXECUTOR_PUBLIC_ENVIRONMENT
                .iter()
                .any(|public| public.eq_ignore_ascii_case(name))
            || !unique.insert(name.to_ascii_uppercase())
        {
            return Err(ExecutorError::InvalidRequest);
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct SecretVariable {
    name: String,
    value: String,
}

impl SecretVariable {
    #[must_use]
    pub fn new(name: String, value: &SecretString) -> Self {
        Self {
            name,
            value: value.expose_secret().to_owned(),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Drop for SecretVariable {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for SecretVariable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretVariable")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutorRequest {
    Command {
        command: Vec<String>,
        environment: Vec<SecretVariable>,
    },
    Script {
        interpreter: PathBuf,
        script: String,
        environment: Vec<SecretVariable>,
    },
}

impl ExecutorRequest {
    #[must_use]
    pub fn command(command: Vec<String>, environment: Vec<SecretVariable>) -> Self {
        Self::Command {
            command,
            environment,
        }
    }

    #[must_use]
    pub fn script(
        interpreter: PathBuf,
        script: &SecretString,
        environment: Vec<SecretVariable>,
    ) -> Self {
        Self::Script {
            interpreter,
            script: script.expose_secret().to_owned(),
            environment,
        }
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ExecutorError> {
        let payload = serde_json::to_vec(self).map_err(|_| ExecutorError::InvalidRequest)?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(ExecutorError::InvalidRequest);
        }
        Ok(Zeroizing::new(payload))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExecutorError> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(ExecutorError::InvalidRequest);
        }
        serde_json::from_slice(bytes).map_err(|_| ExecutorError::InvalidRequest)
    }
}

impl Drop for ExecutorRequest {
    fn drop(&mut self) {
        if let Self::Script { script, .. } = self {
            script.zeroize();
        }
    }
}

impl std::fmt::Debug for ExecutorRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command {
                command,
                environment,
            } => formatter
                .debug_struct("ExecutorRequest::Command")
                .field("command", command)
                .field("environment", environment)
                .finish(),
            Self::Script {
                interpreter,
                environment,
                ..
            } => formatter
                .debug_struct("ExecutorRequest::Script")
                .field("interpreter", interpreter)
                .field("script", &"[REDACTED]")
                .field("environment", environment)
                .finish(),
        }
    }
}

pub fn trusted_executor_path_from(current_executable: &Path) -> Result<PathBuf, ExecutorError> {
    let current = std::fs::canonicalize(current_executable)
        .map_err(|_| ExecutorError::ExecutorUnavailable)?;
    let install_root = current.parent().ok_or(ExecutorError::ExecutorUnavailable)?;
    let candidate = std::fs::canonicalize(install_root.join(EXECUTOR_FILE_NAME))
        .map_err(|_| ExecutorError::ExecutorUnavailable)?;
    if candidate.parent() != Some(install_root) || !candidate.is_file() {
        return Err(ExecutorError::ExecutorUnavailable);
    }
    Ok(candidate)
}

pub fn trusted_executor_path() -> Result<PathBuf, ExecutorError> {
    let current = std::env::current_exe().map_err(|_| ExecutorError::ExecutorUnavailable)?;
    trusted_executor_path_from(&current)
}

#[cfg(windows)]
pub fn run_executor_from_standard_input() -> Result<i32, ExecutorError> {
    windows::run_executor_from_standard_input()
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExecutorError {
    #[error("the hardened Windows executor is unavailable")]
    ExecutorUnavailable,
    #[error("the executor request is invalid")]
    InvalidRequest,
    #[error("the AppContainer profile is unavailable")]
    AppContainerUnavailable,
    #[error("the requested executable is unavailable inside the hardened boundary")]
    ExecutableUnavailable,
    #[error("the executor process could not be started")]
    Spawn,
    #[error("the executor process could not be contained")]
    Containment,
    #[error("the executor process status could not be collected")]
    Wait,
    #[error("the executor output stream failed")]
    Output,
    #[error("the private Script file could not be created or removed")]
    TemporaryScript,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn protocol_redacts_secrets_and_zeroizes_owned_values() {
        let request = ExecutorRequest::command(
            vec!["fixture.exe".to_owned()],
            vec![SecretVariable::new(
                "CLAW_SECRET".to_owned(),
                &SecretString::from("top-secret"),
            )],
        );
        let debug = format!("{request:?}");
        let leaked = debug.contains("top-secret");
        assert!(!leaked, "executor debug output was not redacted");
        assert!(debug.contains("[REDACTED]"));
        let encoded = request.encode().expect("encoded");
        assert!(encoded.len() < MAX_REQUEST_BYTES);
    }

    #[test]
    fn windows_secret_environment_names_reject_empty_and_invalid_names() {
        for names in [
            vec![""],
            vec!["9TOKEN"],
            vec!["BAD-NAME"],
            vec!["BAD=NAME"],
            vec!["BAD NAME"],
            vec!["BAD\0NAME"],
            vec!["NÄME"],
        ] {
            assert_eq!(
                validate_windows_secret_environment_names(names),
                Err(ExecutorError::InvalidRequest)
            );
        }
    }

    #[test]
    fn windows_secret_environment_names_reject_case_insensitive_duplicates() {
        assert_eq!(
            validate_windows_secret_environment_names(["PALLADIN_TOKEN", "palladin_token"]),
            Err(ExecutorError::InvalidRequest)
        );
    }

    #[test]
    fn windows_secret_environment_names_reject_public_environment_collisions() {
        for name in ["path", "SystemRoot", "TEMP", "localappdata"] {
            assert_eq!(
                validate_windows_secret_environment_names([name]),
                Err(ExecutorError::InvalidRequest),
                "accepted reserved public environment name {name}"
            );
        }
    }

    #[test]
    fn windows_secret_environment_names_accept_portable_unique_names() {
        assert_eq!(
            validate_windows_secret_environment_names([
                "PALLADIN_API_KEY",
                "_PALLADIN_PRIVATE_KEY",
                "agent_secret_2",
            ]),
            Ok(())
        );
    }

    #[test]
    fn executor_must_be_a_fixed_sibling_of_the_worker() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let worker = directory.path().join("palladin-worker.exe");
        let executor = directory.path().join(EXECUTOR_FILE_NAME);
        fs::write(&worker, b"worker").expect("worker");
        fs::write(&executor, b"executor").expect("executor");
        assert_eq!(
            trusted_executor_path_from(&worker).expect("trusted executor"),
            fs::canonicalize(executor).expect("canonical executor")
        );
    }
}
