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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptInterpreter {
    Node,
    Python,
    Shell,
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
        interpreter_kind: ScriptInterpreter,
        script: String,
        stdin: String,
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
        interpreter_kind: ScriptInterpreter,
        script: &SecretString,
        stdin: &SecretString,
        environment: Vec<SecretVariable>,
    ) -> Self {
        Self::Script {
            interpreter,
            interpreter_kind,
            script: script.expose_secret().to_owned(),
            stdin: stdin.expose_secret().to_owned(),
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
        if let Self::Script { script, stdin, .. } = self {
            script.zeroize();
            stdin.zeroize();
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

/// Produces the private on-disk source for an interpreter kind that the broker
/// has already resolved through its exact allowlist. Node Scripts are wrapped
/// in an async CommonJS function so the cross-platform contract keeps both
/// top-level `await` and the controlled `require`/module globals. Other
/// allowlisted interpreters keep the source unchanged. The allowlisted kind is
/// carried explicitly because canonicalized aliases may have another basename.
pub fn prepare_private_script_source(
    interpreter_kind: ScriptInterpreter,
    script: &str,
) -> Result<Zeroizing<Vec<u8>>, ExecutorError> {
    if matches!(interpreter_kind, ScriptInterpreter::Node) {
        let encoded = Zeroizing::new(
            serde_json::to_string(script).map_err(|_| ExecutorError::InvalidRequest)?,
        );
        let wrapper = Zeroizing::new(format!(
            "const Module=require(\"node:module\"),path=require(\"node:path\"),f=__filename,m=module,AsyncFunction=Object.getPrototypeOf(async function(){{}}).constructor;try{{const run=new AsyncFunction(\"require\",\"module\",\"exports\",\"__filename\",\"__dirname\",{});run(require,m,m.exports,f,path.dirname(f)).catch(()=>{{process.exitCode=1}})}}catch{{process.exitCode=1}}",
            encoded.as_str(),
        ));
        return Ok(Zeroizing::new(wrapper.as_bytes().to_vec()));
    }
    Ok(Zeroizing::new(script.as_bytes().to_vec()))
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

    #[test]
    fn private_source_preserves_an_allowlisted_shell_after_canonicalization() {
        let source = "printf '%s' ok";
        let prepared = prepare_private_script_source(ScriptInterpreter::Shell, source)
            .expect("prepared shell source");

        assert_eq!(prepared.as_slice(), source.as_bytes());
    }

    #[test]
    fn private_source_wraps_node_by_allowlisted_kind_after_alias_canonicalization() {
        let source = "await Promise.resolve(); module.exports = 1;";
        let prepared = prepare_private_script_source(ScriptInterpreter::Node, source)
            .expect("prepared Node source");
        let prepared = std::str::from_utf8(&prepared).expect("UTF-8 wrapper");

        assert!(prepared.contains("AsyncFunction"));
        assert!(prepared.contains("module"));
        assert!(!prepared.starts_with(source));
    }
}
