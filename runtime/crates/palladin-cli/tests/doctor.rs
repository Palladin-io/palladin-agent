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
