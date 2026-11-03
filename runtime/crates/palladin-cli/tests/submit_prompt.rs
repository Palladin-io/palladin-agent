use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SECRET_CANARY: &str = "piped-model-secret-canary-7f3a";

/// `--from-prompt` accepts only a human at an interactive terminal: a pipe or file on stdin could
/// carry model output, an environment variable or a file, which the contract forbids.
#[test]
fn from_prompt_with_non_terminal_stdin_is_refused_before_reading_or_any_request() {
    let home = tempfile::tempdir().expect("home");
    for json in [true, false] {
        let mut arguments = vec![
            "submit",
            "new",
            "--type",
            "credential",
            "--label",
            "Example",
            "--username",
            "agent@example.invalid",
            "--from-prompt",
        ];
        if json {
            arguments.push("--json");
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_palladin"))
            .env_clear()
            .env("HOME", home.path())
            .args(&arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn runtime");
        // Keep the pipe open and never close it: a runtime that read stdin would block here.
        let stdin = child.stdin.take().expect("stdin");
        let started = Instant::now();
        while child.try_wait().expect("wait").is_none() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the runtime waited for piped input instead of refusing it"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(stdin);
        let output = child.wait_with_output().expect("output");
        let stdout = String::from_utf8(output.stdout).expect("stdout");
        let stderr = String::from_utf8(output.stderr).expect("stderr");
        assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
        assert!(
            stderr.contains(
                "Invalid input: --from-prompt requires an interactive terminal; use --generate or run it in a terminal."
            ),
            "{stderr}"
        );
        if json {
            let result: serde_json::Value = serde_json::from_str(&stdout).expect("agentResult");
            assert_eq!(result["submissionStatus"], "not-saved");
            assert_eq!(result["code"], "invalid-input");
        }
        assert!(
            !home.path().join(".palladin").exists(),
            "no profile state is opened or created"
        );
    }

    // A value that was already written to the pipe is never consumed or echoed either.
    let mut child = Command::new(env!("CARGO_BIN_EXE_palladin"))
        .env_clear()
        .env("HOME", home.path())
        .args([
            "submit",
            "update",
            "--type",
            "credential",
            "--vault",
            "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e",
            "--entry",
            "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f",
            "--from-prompt",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runtime");
    let mut stdin = child.stdin.take().expect("stdin");
    let _ = writeln!(stdin, "{SECRET_CANARY}");
    drop(stdin);
    let output = child.wait_with_output().expect("output");
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(SECRET_CANARY));
}
