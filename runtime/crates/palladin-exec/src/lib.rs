#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(not(windows))]
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use command_group::{AsyncCommandGroup, AsyncGroupChild};
use palladin_core::environment::{is_dangerous_name, sanitize_child};
use palladin_credential::secret::{ParsedSecret, env_field_key};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use thiserror::Error;
#[cfg(windows)]
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
use palladin_windows_executor::{ExecutorRequest, SecretVariable};

const INHERITED_ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "TZ",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
];

const DANGEROUS_EXACT_ENVIRONMENT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PROMPT_COMMAND",
    "PS4",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUSTC_WRAPPER",
    "SSLKEYLOGFILE",
    "ZDOTDIR",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorOutput {
    Terminal,
    Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub cancelled: bool,
}

pub struct SecretEnvironment {
    values: BTreeMap<String, SecretString>,
}

impl SecretEnvironment {
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn for_credential(secret: &ParsedSecret) -> Self {
        let mut environment = Self::new();
        environment.insert_trusted("CLAW_SECRET", secret.password.clone());
        if let Some(username) = &secret.username {
            environment.insert_trusted("CLAW_USERNAME", username.clone());
            environment.insert_trusted("CLAW_PASSWORD", secret.password.clone());
        }
        for (key, value) in &secret.fields {
            let key = env_field_key(key);
            if key.is_empty() {
                continue;
            }
            let name = format!("CLAW_{key}");
            if !environment.contains_case_insensitive(&name) {
                environment.insert_trusted(name, value.clone());
            }
        }
        environment
    }

    pub fn insert_reference(
        &mut self,
        name: &str,
        value: SecretString,
    ) -> Result<(), EnvironmentError> {
        validate_reference_name(name)?;
        if self.contains_case_insensitive(name) {
            return Err(EnvironmentError::DuplicateName);
        }
        self.values.insert(name.to_owned(), value);
        Ok(())
    }

    pub fn merge_references(&mut self, other: Self) -> Result<(), EnvironmentError> {
        for (name, value) in other.values {
            self.insert_reference(&name, value)?;
        }
        Ok(())
    }

    fn insert_trusted(&mut self, name: impl Into<String>, value: SecretString) {
        self.values.insert(name.into(), value);
    }

    fn contains_case_insensitive(&self, candidate: &str) -> bool {
        self.values
            .keys()
            .any(|name| name.eq_ignore_ascii_case(candidate))
    }

    #[cfg(windows)]
    fn into_executor_variables(self) -> Vec<SecretVariable> {
        self.values
            .into_iter()
            .map(|(name, value)| SecretVariable::new(name, &value))
            .collect()
    }
}

impl Default for SecretEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecretEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretEnvironment")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interpreter {
    Bash,
    Sh,
    Node,
    Python,
}

pub struct ResolvedInterpreter {
    executable: PathBuf,
}

impl std::fmt::Debug for ResolvedInterpreter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedInterpreter([REDACTED PATH])")
    }
}

impl Interpreter {
    #[must_use]
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Sh => "sh",
            Self::Node => "node",
            #[cfg(windows)]
            Self::Python => "python",
            #[cfg(not(windows))]
            Self::Python => "python3",
        }
    }
}

pub fn allowed_interpreter(value: &str) -> Result<Interpreter, ExecError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "bash" => Ok(Interpreter::Bash),
        "sh" => Ok(Interpreter::Sh),
        "node" => Ok(Interpreter::Node),
        "python" => Ok(Interpreter::Python),
        _ => Err(ExecError::UnsupportedInterpreter),
    }
}

pub fn resolve_interpreter(value: &str) -> Result<ResolvedInterpreter, ExecError> {
    let interpreter = allowed_interpreter(value)?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    resolve_interpreter_from(interpreter, &path)
}

fn resolve_interpreter_from(
    interpreter: Interpreter,
    path: &OsStr,
) -> Result<ResolvedInterpreter, ExecError> {
    let executable = interpreter.executable();
    for directory in std::env::split_paths(path).filter(|path| path.is_absolute()) {
        let candidate = interpreter_candidate(&directory, executable);
        let Ok(executable) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if !valid_interpreter_candidate(&executable) {
            continue;
        }
        return Ok(ResolvedInterpreter { executable });
    }
    Err(ExecError::InterpreterUnavailable)
}

#[cfg(windows)]
fn interpreter_candidate(directory: &Path, executable: &str) -> PathBuf {
    directory.join(format!("{executable}.exe"))
}

#[cfg(not(windows))]
fn interpreter_candidate(directory: &Path, executable: &str) -> PathBuf {
    directory.join(executable)
}

#[cfg(unix)]
fn valid_interpreter_candidate(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(candidate) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn valid_interpreter_candidate(candidate: &Path) -> bool {
    candidate.is_file()
        && candidate
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

pub async fn run_command(
    command: &[String],
    environment: SecretEnvironment,
    output: OperatorOutput,
    cancellation: &CancellationToken,
) -> Result<ExecResult, ExecError> {
    validate_command(command)?;
    #[cfg(windows)]
    {
        return run_windows_request(
            ExecutorRequest::command(command.to_vec(), environment.into_executor_variables()),
            output,
            cancellation,
        )
        .await;
    }
    #[cfg(not(windows))]
    {
        let (program, arguments) = command.split_first().ok_or(ExecError::MissingCommand)?;
        if cancellation.is_cancelled() {
            return Ok(ExecResult {
                exit_code: 130,
                cancelled: true,
            });
        }

        let mut process = Command::new(program);
        process
            .args(arguments)
            .env_clear()
            .envs(sanitized_environment())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        for (name, value) in &environment.values {
            process.env(name, value.expose_secret());
        }
        sanitize_child(process.as_std_mut());
        configure_output(&mut process, output);

        let mut child = match process.group().kill_on_drop(true).spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ExecResult {
                    exit_code: 127,
                    cancelled: false,
                });
            }
            Err(_) => return Err(ExecError::Spawn),
        };
        drop(process);
        drop(environment);
        let (status, cancelled) = wait_for_group(&mut child, cancellation).await?;
        Ok(ExecResult {
            exit_code: if cancelled {
                130
            } else {
                status.code().unwrap_or(1)
            },
            cancelled,
        })
    }
}

#[cfg(windows)]
async fn run_windows_request(
    request: ExecutorRequest,
    output: OperatorOutput,
    cancellation: &CancellationToken,
) -> Result<ExecResult, ExecError> {
    if cancellation.is_cancelled() {
        return Ok(ExecResult {
            exit_code: 130,
            cancelled: true,
        });
    }
    let payload = request
        .encode()
        .map_err(|_| ExecError::HardenedExecutorProtocol)?;
    drop(request);
    let length = u32::try_from(payload.len())
        .map_err(|_| ExecError::HardenedExecutorProtocol)?
        .to_be_bytes();
    let executable = palladin_windows_executor::trusted_executor_path()
        .map_err(|_| ExecError::HardenedExecutorUnavailable)?;
    let mut process = Command::new(executable);
    process
        .env_clear()
        .envs(sanitized_environment())
        .stdin(Stdio::piped())
        .kill_on_drop(true);
    sanitize_child(process.as_std_mut());
    configure_output(&mut process, output);
    let mut child = process
        .group()
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ExecError::HardenedExecutorUnavailable)?;
    drop(process);
    let mut standard_input = child
        .inner()
        .stdin
        .take()
        .ok_or(ExecError::HardenedExecutorProtocol)?;
    let request_write = async {
        standard_input.write_all(&length).await?;
        standard_input.write_all(&payload).await?;
        standard_input.shutdown().await
    };
    tokio::select! {
        result = request_write => {
            result.map_err(|_| ExecError::HardenedExecutorProtocol)?;
        }
        () = cancellation.cancelled() => {
            let _ = child.kill().await;
            return Ok(ExecResult {
                exit_code: 130,
                cancelled: true,
            });
        }
    }
    drop(standard_input);
    drop(payload);
    let (status, cancelled) = wait_for_group(&mut child, cancellation).await?;
    Ok(ExecResult {
        exit_code: if cancelled {
            130
        } else {
            status.code().unwrap_or(1)
        },
        cancelled,
    })
}

pub fn validate_command(command: &[String]) -> Result<(), ExecError> {
    let Some((program, _arguments)) = command.split_first() else {
        return Err(ExecError::MissingCommand);
    };
    if program.trim().is_empty()
        || command.len() > 128
        || command.iter().map(String::len).sum::<usize>() > 65_536
        || command
            .iter()
            .any(|argument| argument.contains('\0') || argument.chars().count() > 8192)
    {
        return Err(ExecError::InvalidArgument);
    }
    #[cfg(windows)]
    if is_windows_command_script(program) {
        return Err(ExecError::ImplicitShellForbidden);
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_command_script(program: &str) -> bool {
    let lowercase = program.trim().to_ascii_lowercase();
    lowercase.ends_with(".bat") || lowercase.ends_with(".cmd")
}

async fn wait_for_group(
    child: &mut AsyncGroupChild,
    cancellation: &CancellationToken,
) -> Result<(std::process::ExitStatus, bool), ExecError> {
    loop {
        if cancellation.is_cancelled() {
            let _ = child.kill().await;
            return Ok((cancelled_status(), true));
        }
        if let Some(status) = child.try_wait().map_err(|_| ExecError::Wait)? {
            return Ok((status, false));
        }
        tokio::select! {
            () = cancellation.cancelled() => {}
            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }
    }
}

fn cancelled_status() -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(9)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(130)
    }
}

pub async fn run_script(
    script: &SecretString,
    interpreter: &ResolvedInterpreter,
    environment: SecretEnvironment,
    output: OperatorOutput,
    cancellation: &CancellationToken,
) -> Result<ExecResult, ExecError> {
    #[cfg(windows)]
    {
        return run_windows_request(
            ExecutorRequest::script(
                interpreter.executable.clone(),
                script,
                environment.into_executor_variables(),
            ),
            output,
            cancellation,
        )
        .await;
    }
    #[cfg(not(windows))]
    {
        let temporary = TempScript::new(script)?;
        let command = vec![
            interpreter.executable.to_string_lossy().into_owned(),
            temporary.path().to_string_lossy().into_owned(),
        ];
        let result = run_command(&command, environment, output, cancellation).await;
        temporary.close()?;
        result
    }
}

fn sanitized_environment() -> BTreeMap<OsString, OsString> {
    sanitized_environment_from(std::env::vars_os())
}

fn sanitized_environment_from(
    source: impl IntoIterator<Item = (OsString, OsString)>,
) -> BTreeMap<OsString, OsString> {
    source
        .into_iter()
        .filter(|(name, _)| {
            INHERITED_ENVIRONMENT
                .iter()
                .any(|allowed| os_name_eq(name, allowed))
        })
        .collect()
}

#[cfg(windows)]
fn os_name_eq(name: &OsStr, candidate: &str) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case(candidate)
}

#[cfg(not(windows))]
fn os_name_eq(name: &OsStr, candidate: &str) -> bool {
    name == candidate
}

pub fn validate_reference_name(name: &str) -> Result<(), EnvironmentError> {
    let mut characters = name.chars();
    if !characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        || characters.any(|character| character != '_' && !character.is_ascii_alphanumeric())
    {
        return Err(EnvironmentError::InvalidName);
    }
    let uppercase = name.to_ascii_uppercase();
    if INHERITED_ENVIRONMENT.contains(&uppercase.as_str())
        || DANGEROUS_EXACT_ENVIRONMENT.contains(&uppercase.as_str())
        || is_dangerous_name(&uppercase)
        || uppercase.starts_with("LD_")
        || uppercase.starts_with("DYLD_")
        || uppercase.starts_with("PALLADIN_")
        || uppercase.starts_with("CLAW_")
    {
        return Err(EnvironmentError::ReservedName);
    }
    Ok(())
}

fn configure_output(process: &mut Command, output: OperatorOutput) {
    match output {
        OperatorOutput::Terminal => {
            process.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        }
        OperatorOutput::Discard => {
            process.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
}

#[cfg(not(windows))]
struct TempScript {
    directory: Option<TempDir>,
    path: PathBuf,
}

#[cfg(not(windows))]
impl TempScript {
    fn new(script: &SecretString) -> Result<Self, ExecError> {
        let directory = tempfile::Builder::new()
            .prefix("palladin-script-")
            .tempdir()
            .map_err(|_| ExecError::TemporaryScript)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ExecError::TemporaryScript)?;
        }
        let path = directory.path().join("script");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| ExecError::TemporaryScript)?;
        file.write_all(script.expose_secret().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ExecError::TemporaryScript)?;
        Ok(Self {
            directory: Some(directory),
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn close(mut self) -> Result<(), ExecError> {
        std::fs::remove_file(&self.path).map_err(|_| ExecError::TemporaryCleanup)?;
        self.path.clear();
        if let Some(directory) = self.directory.take() {
            directory.close().map_err(|_| ExecError::TemporaryCleanup)?;
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Drop for TempScript {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EnvironmentError {
    #[error("environment variable name is invalid")]
    InvalidName,
    #[error("environment variable name is reserved by the secure runtime")]
    ReservedName,
    #[error("environment variable name is duplicated")]
    DuplicateName,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExecError {
    #[error("no executable was provided")]
    MissingCommand,
    #[error("a command argument is invalid")]
    InvalidArgument,
    #[error("Windows command scripts require an explicit shell")]
    ImplicitShellForbidden,
    #[error("the Script entry uses an unsupported interpreter")]
    UnsupportedInterpreter,
    #[error("the Script entry interpreter is not installed as an executable in PATH")]
    InterpreterUnavailable,
    #[error("the command could not be started")]
    Spawn,
    #[error("the command status could not be collected")]
    Wait,
    #[error("the private temporary script could not be created")]
    TemporaryScript,
    #[error("the private temporary script could not be deleted")]
    TemporaryCleanup,
    #[error("the signed hardened Windows executor is unavailable")]
    HardenedExecutorUnavailable,
    #[error("the hardened Windows executor rejected its private request")]
    HardenedExecutorProtocol,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(not(windows))]
    use std::io::Read;
    use std::time::Duration;

    use palladin_credential::secret::parse_secret;
    use secrecy::SecretString;

    use super::*;

    #[test]
    fn sanitized_environment_is_a_positive_allowlist() {
        let environment = sanitized_environment_from([
            (OsString::from("PATH"), OsString::from("fixture-path")),
            (OsString::from("NODE_OPTIONS"), OsString::from("attack")),
            (
                OsString::from("AWS_SECRET_ACCESS_KEY"),
                OsString::from("secret"),
            ),
            (OsString::from("HOME"), OsString::from("fixture-home")),
        ]);
        assert_eq!(environment.len(), 2);
        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&OsString::from("fixture-path"))
        );
        assert_eq!(
            environment.get(OsStr::new("HOME")),
            Some(&OsString::from("fixture-home"))
        );
    }

    #[test]
    fn references_cannot_replace_loader_interpreter_or_runtime_environment() {
        for name in [
            "PATH",
            "Path",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PALLADIN_HOME",
            "CLAW_SECRET",
        ] {
            let mut environment = SecretEnvironment::new();
            assert!(matches!(
                environment.insert_reference(name, SecretString::from("fixture")),
                Err(EnvironmentError::ReservedName)
            ));
        }
    }

    #[test]
    fn reference_names_are_portable_and_case_insensitively_unique() {
        let mut environment = SecretEnvironment::new();
        environment
            .insert_reference("TOKEN", SecretString::from("one"))
            .expect("valid");
        assert_eq!(
            environment.insert_reference("token", SecretString::from("two")),
            Err(EnvironmentError::DuplicateName)
        );
        for invalid in ["", "1TOKEN", "BAD-NAME", "A=B", "ŻÓŁĆ"] {
            assert_eq!(
                SecretEnvironment::new().insert_reference(invalid, SecretString::from("fixture")),
                Err(EnvironmentError::InvalidName)
            );
        }
    }

    #[test]
    fn interpreter_allowlist_is_exact_and_normalized() {
        assert_eq!(allowed_interpreter(" Bash "), Ok(Interpreter::Bash));
        assert_eq!(allowed_interpreter("SH"), Ok(Interpreter::Sh));
        assert_eq!(allowed_interpreter("node"), Ok(Interpreter::Node));
        assert_eq!(allowed_interpreter("python"), Ok(Interpreter::Python));
        for denied in ["", "ruby", "sh -c", "/bin/sh", "node\0--eval"] {
            assert_eq!(
                allowed_interpreter(denied),
                Err(ExecError::UnsupportedInterpreter)
            );
        }
    }

    #[test]
    fn interpreter_is_resolved_to_an_absolute_prevalidated_executable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let candidate = interpreter_candidate(directory.path(), Interpreter::Node.executable());
        std::fs::write(&candidate, b"synthetic executable").expect("candidate");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("directory permissions");
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                .expect("candidate permissions");
        }
        let path = std::env::join_paths([
            PathBuf::from("relative-attacker"),
            directory.path().to_owned(),
        ])
        .expect("PATH");
        let resolved = resolve_interpreter_from(Interpreter::Node, &path).expect("resolved");
        assert!(resolved.executable.is_absolute());
        assert_eq!(
            resolved.executable,
            std::fs::canonicalize(candidate).expect("canonical")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn private_script_is_removed_by_raii() {
        let path = {
            let script = TempScript::new(&SecretString::from("fixture")).expect("temporary script");
            let path = script.path().to_owned();
            assert!(path.exists());
            path
        };
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_script_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let script = TempScript::new(&SecretString::from("fixture")).expect("temporary script");
        let mode = std::fs::metadata(script.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let directory_mode = std::fs::metadata(script.path().parent().expect("parent"))
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
    }

    #[tokio::test]
    async fn missing_executable_is_reported_without_an_os_error_or_output() {
        let command = vec![format!(
            "palladin-command-that-does-not-exist-{}",
            std::process::id()
        )];
        let result = run_command(
            &command,
            SecretEnvironment::new(),
            OperatorOutput::Discard,
            &CancellationToken::new(),
        )
        .await
        .expect("safe result");
        assert_eq!(
            result,
            ExecResult {
                exit_code: 127,
                cancelled: false,
            }
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn child_gets_only_scoped_secrets_and_protocol_stdin_is_eof() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("observed");
        let parsed = parse_secret(
            br#"{"username":"fixture-user","password":"fixture-password","region":"eu"}"#,
        )
        .expect("credential");
        let mut environment = SecretEnvironment::for_credential(&parsed);
        environment
            .insert_reference("TEST_ROOT", marker.to_string_lossy().into_owned().into())
            .expect("test marker");
        let result = run_command(
            &test_child_command("scoped_environment_child"),
            environment,
            OperatorOutput::Discard,
            &CancellationToken::new(),
        )
        .await
        .expect("child result");
        assert_eq!(result.exit_code, 0);
        assert_eq!(std::fs::read_to_string(marker).expect("marker"), "ok");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn direct_spawn_never_interprets_shell_metacharacters() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("observed");
        let mut environment = SecretEnvironment::new();
        environment
            .insert_reference("TEST_ROOT", marker.to_string_lossy().into_owned().into())
            .expect("test marker");
        let mut command = test_child_command("literal_argument_child");
        command.push("$CLAW_SECRET;$(touch attacker)|&<>".to_owned());
        let result = run_command(
            &command,
            environment,
            OperatorOutput::Discard,
            &CancellationToken::new(),
        )
        .await
        .expect("child result");
        assert_eq!(result.exit_code, 0);
        assert_eq!(std::fs::read_to_string(marker).expect("marker"), "ok");
        assert!(!directory.path().join("attacker").exists());
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "subprocess helper"]
    fn scoped_environment_child() {
        let mut byte = [0_u8; 1];
        let stdin_is_eof = std::io::stdin().read(&mut byte).expect("stdin") == 0;
        let correct = std::env::var("CLAW_SECRET").as_deref() == Ok("fixture-password")
            && std::env::var("CLAW_USERNAME").as_deref() == Ok("fixture-user")
            && std::env::var("CLAW_REGION").as_deref() == Ok("eu")
            && std::env::var_os("AWS_SECRET_ACCESS_KEY").is_none()
            && stdin_is_eof;
        let marker = std::env::var("TEST_ROOT").expect("test root");
        std::fs::write(marker, if correct { "ok" } else { "invalid" }).expect("marker");
        assert!(correct);
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "subprocess helper"]
    fn literal_argument_child() {
        let literal = std::env::args().nth(5).expect("literal argument");
        let marker = std::env::var("TEST_ROOT").expect("test root");
        let correct = literal == "$CLAW_SECRET;$(touch attacker)|&<>";
        std::fs::write(marker, if correct { "ok" } else { "invalid" }).expect("marker");
        assert!(correct);
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn cancellation_terminates_the_entire_process_tree() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut environment = SecretEnvironment::new();
        environment
            .insert_reference(
                "TEST_ROOT",
                directory.path().to_string_lossy().into_owned().into(),
            )
            .expect("test root");
        let ready = directory.path().join("ready");
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let waiter = tokio::spawn(async move {
            for _ in 0..250 {
                if ready.exists() {
                    signal.cancel();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            signal.cancel();
        });
        let result = run_command(
            &test_child_command("process_tree_child"),
            environment,
            OperatorOutput::Discard,
            &cancellation,
        )
        .await
        .expect("cancelled result");
        waiter.await.expect("waiter");
        assert_eq!(result.exit_code, 130);
        assert!(result.cancelled);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!directory.path().join("survived").exists());
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "subprocess helper"]
    fn process_tree_child() {
        let mut grandchild =
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--ignored",
                    "--exact",
                    "tests::process_tree_grandchild",
                    "--nocapture",
                ])
                .spawn()
                .expect("grandchild");
        let root = std::env::var("TEST_ROOT").expect("test root");
        std::fs::write(Path::new(&root).join("ready"), b"ready").expect("ready");
        std::thread::sleep(Duration::from_secs(30));
        let _ = grandchild.wait();
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "subprocess helper"]
    fn process_tree_grandchild() {
        std::thread::sleep(Duration::from_secs(1));
        let root = std::env::var("TEST_ROOT").expect("test root");
        std::fs::write(Path::new(&root).join("survived"), b"survived").expect("survived");
    }

    #[cfg(not(windows))]
    fn test_child_command(name: &str) -> Vec<String> {
        vec![
            std::env::current_exe()
                .expect("test executable")
                .to_string_lossy()
                .into_owned(),
            "--ignored".to_owned(),
            "--exact".to_owned(),
            format!("tests::{name}"),
            "--nocapture".to_owned(),
        ]
    }

    #[test]
    fn command_validation_rejects_nul_and_resource_abuse() {
        assert_eq!(
            validate_command(&["program".to_owned(), "bad\0argument".to_owned()]),
            Err(ExecError::InvalidArgument)
        );
        assert_eq!(
            validate_command(&vec!["argument".to_owned(); 129]),
            Err(ExecError::InvalidArgument)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_command_scripts_cannot_trigger_an_implicit_shell() {
        for program in ["fixture.cmd", "FIXTURE.BAT", r"C:\fixture\script.Cmd"] {
            assert_eq!(
                validate_command(&[program.to_owned()]),
                Err(ExecError::ImplicitShellForbidden)
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_executor_delivers_only_scoped_secret_with_null_stdin() {
        let parsed = parse_secret(
            br#"{"username":"fixture-user","password":"fixture-password","region":"eu"}"#,
        )
        .expect("credential");
        // Windows PowerShell 5.1 cannot initialize reliably under an AppContainer
        // token, so cmd.exe is the native boundary probe for these assertions.
        let command = vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "setlocal EnableExtensions DisableDelayedExpansion & set /p PALLADIN_INPUT= & if not errorlevel 1 exit /b 90 & if not x%CLAW_SECRET%==xfixture-password exit /b 91 & if not x%CLAW_USERNAME%==xfixture-user exit /b 92 & if not x%CLAW_REGION%==xeu exit /b 93 & if defined PALLADIN_API_KEY exit /b 94 & exit /b 0".to_owned(),
        ];
        let result = run_command(
            &command,
            SecretEnvironment::for_credential(&parsed),
            OperatorOutput::Discard,
            &CancellationToken::new(),
        )
        .await
        .expect("contained Windows execution");
        assert_eq!(result.exit_code, 0);
        assert!(!result.cancelled);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_executor_propagates_the_exact_child_exit_code() {
        let command = vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "exit /b 23".to_owned(),
        ];
        let result = run_command(
            &command,
            SecretEnvironment::new(),
            OperatorOutput::Discard,
            &CancellationToken::new(),
        )
        .await
        .expect("contained Windows execution");
        assert_eq!(result.exit_code, 23);
        assert!(!result.cancelled);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_cancellation_terminates_executor_with_a_descendant_promptly() {
        let command = vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "start /B cmd.exe /D /C for /L %i in (0,0,0) do @rem & for /L %i in (0,0,0) do @rem".to_owned(),
        ];
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let cancel = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            signal.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_command(
                &command,
                SecretEnvironment::new(),
                OperatorOutput::Discard,
                &cancellation,
            ),
        )
        .await
        .expect("Windows cancellation timed out")
        .expect("contained Windows cancellation");
        cancel.await.expect("cancellation signal");
        assert_eq!(result.exit_code, 130);
        assert!(result.cancelled);
    }
}
