use std::process::Command;

fn runtime() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_palladin"));
    command.env_clear();
    command
}

#[test]
fn version_works_without_reading_project_files() {
    let project = tempfile::tempdir().expect("temp project");
    std::fs::write(
        project.path().join("palladin-plugin.js"),
        "throw 'must not load'",
    )
    .expect("malicious fixture");

    let output = runtime()
        .current_dir(project.path())
        .arg("--version")
        .output()
        .expect("run version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        concat!("palladin ", env!("CARGO_PKG_VERSION"), "\n")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_is_secretless_in_a_clean_environment() {
    let project = tempfile::tempdir().expect("temp project");
    let output = runtime()
        .current_dir(project.path())
        .arg("doctor")
        .output()
        .expect("run doctor");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("identity-opened: no"));
    assert!(stdout.contains("project-runtime-dependencies: disabled"));
    assert!(stdout.contains("environment: safe"));
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_reports_only_the_name_of_a_dangerous_variable() {
    let synthetic_value = "synthetic-value-must-not-appear";
    let output = runtime()
        .env("NODE_OPTIONS", synthetic_value)
        .arg("doctor")
        .output()
        .expect("run unsafe doctor");

    assert_eq!(output.status.code(), Some(78));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stdout.contains("environment: unsafe"));
    assert!(stdout.contains("dangerous-variable-names: NODE_OPTIONS"));
    assert!(!stdout.contains(synthetic_value));
    assert!(!stderr.contains(synthetic_value));
}

#[test]
fn legacy_positional_api_key_is_rejected_without_echoing_it() {
    let synthetic = "pl_synthetic_must_not_appear";
    let output = runtime()
        .args(["connect", synthetic])
        .output()
        .expect("run connect");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(!stdout.contains(synthetic));
    assert!(!stderr.contains(synthetic));
    assert!(stderr.contains("forbidden in argv"));
}

#[test]
fn connect_help_has_no_api_key_positional_argument() {
    let output = runtime()
        .args(["connect", "--help"])
        .output()
        .expect("connect help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(!stdout.to_ascii_lowercase().contains("<api-key>"));
    assert!(stdout.contains("--api-key-stdin"));
}

#[test]
fn invalid_stdin_api_key_is_not_echoed() {
    use std::io::Write;
    use std::process::Stdio;

    let synthetic = "synthetic-invalid-key-must-not-appear";
    let mut child = runtime()
        .args(["connect", "--api-key-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn connect");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{synthetic}\n").as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(!stdout.contains(synthetic));
    assert!(!stderr.contains(synthetic));
}

#[test]
fn palladin_home_is_rejected_without_revealing_its_value() {
    let synthetic = "/synthetic/private/path/must-not-appear";
    let output = runtime()
        .env("PALLADIN_HOME", synthetic)
        .arg("agents")
        .arg("list")
        .output()
        .expect("run agents list");
    assert_eq!(output.status.code(), Some(78));
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(stdout.contains("PALLADIN_HOME"));
    assert!(!stdout.contains(synthetic));
    assert!(!stderr.contains(synthetic));
}
