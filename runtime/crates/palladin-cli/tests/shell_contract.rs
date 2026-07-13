#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output};

fn runtime_copy() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("palladin shell contract ")
        .tempdir()
        .expect("temporary directory");
    let binary_name = if cfg!(windows) {
        "palladin-runtime.exe"
    } else {
        "palladin runtime"
    };
    let target = root.path().join(binary_name);
    std::fs::copy(env!("CARGO_BIN_EXE_palladin"), &target).expect("copy runtime");
    (root, target)
}

fn assert_version(output: Output, shell: &str) {
    assert!(output.status.success(), "{shell}: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
    assert_eq!(
        stdout,
        concat!("palladin ", env!("CARGO_PKG_VERSION"), "\n"),
        "{shell} stdout"
    );
    assert!(output.stderr.is_empty(), "{shell} stderr: {output:?}");
}

fn assert_usage_error(output: Output, shell: &str) {
    assert_eq!(output.status.code(), Some(2), "{shell}: {output:?}");
    assert!(output.stdout.is_empty(), "{shell} stdout: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr).replace("\r\n", "\n");
    assert!(
        stderr.starts_with("error: unrecognized subcommand 'definitely-unknown'\n"),
        "{shell} stderr: {stderr}"
    );
}

#[cfg(unix)]
fn unix_shell(shell: &Path, runtime: &Path) -> Output {
    Command::new(shell)
        .args(["-c", "\"$1\" --version", "palladin-shell"])
        .arg(runtime)
        .output()
        .expect("run Unix shell")
}

#[cfg(unix)]
fn unix_shell_usage_error(shell: &Path, runtime: &Path) -> Output {
    Command::new(shell)
        .args(["-c", "\"$1\" definitely-unknown", "palladin-shell"])
        .arg(runtime)
        .output()
        .expect("run Unix shell usage error")
}

#[cfg(unix)]
#[test]
fn bash_and_zsh_preserve_path_quoting_stdout_and_exit_code() {
    let (_root, runtime) = runtime_copy();
    assert_version(unix_shell(Path::new("/bin/bash"), &runtime), "bash");
    assert_usage_error(
        unix_shell_usage_error(Path::new("/bin/bash"), &runtime),
        "bash",
    );

    let zsh = Path::new("/bin/zsh");
    if zsh.exists() {
        assert_version(unix_shell(zsh, &runtime), "zsh");
        assert_usage_error(unix_shell_usage_error(zsh, &runtime), "zsh");
    }
}

#[cfg(windows)]
#[test]
fn cmd_and_powershell_preserve_path_quoting_stdout_and_exit_code() {
    let (root, runtime) = runtime_copy();
    assert!(root.path().to_string_lossy().contains(' '));
    let cmd = std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
    assert_version(
        Command::new(&cmd)
            .current_dir(root.path())
            .args(["/D", "/S", "/C", ".\\palladin-runtime.exe --version"])
            .output()
            .expect("run cmd"),
        "cmd",
    );
    assert_usage_error(
        Command::new(cmd)
            .current_dir(root.path())
            .args([
                "/D",
                "/S",
                "/C",
                ".\\palladin-runtime.exe definitely-unknown",
            ])
            .output()
            .expect("run cmd usage error"),
        "cmd",
    );

    assert_version(
        Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "& $args[0] --version",
            ])
            .arg(&runtime)
            .output()
            .expect("run PowerShell"),
        "PowerShell",
    );
    assert_usage_error(
        Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "& $args[0] definitely-unknown; exit $LASTEXITCODE",
            ])
            .arg(&runtime)
            .output()
            .expect("run PowerShell usage error"),
        "PowerShell",
    );
}
